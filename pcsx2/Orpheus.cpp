// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

// Orpheus HTTP API — see Orpheus.h.
//
// A tiny HTTP/1.1 server, run on its own thread (mirroring PINE's lifecycle),
// that bridges external tools to PCSX2's debugger core. This first increment
// exposes read-only endpoints:
//
//   GET /status                          emulator/VM state
//   GET /registers?cpu=ee|iop            full register dump
//   GET /memory?cpu=ee|iop&addr=&len=    hex bytes of a memory range
//
// Reads are performed directly (PINE-style), which is racy against a running
// core but crash- and deadlock-free. Mutating/control endpoints (breakpoints,
// watchpoints, pause/resume/step) will marshal onto the CPU thread via
// Host::RunOnCPUThread in a later increment.

#include "Orpheus.h"

#include "DebugTools/Breakpoints.h"
#include "DebugTools/DebugInterface.h"
#include "Host.h"
#include "VMManager.h"

#include "common/Console.h"
#include "common/Pcsx2Types.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)

// The HTTP server is POSIX-socket based; provide a stub so the fork still builds
// on Windows. (PINE-style Winsock support can be added later.)
namespace OrpheusServer
{
	bool IsInitialized() { return false; }
	int GetPort() { return 0; }
	bool Initialize(int)
	{
		Console.Warning("Orpheus: HTTP API is not implemented on Windows yet.");
		return false;
	}
	void Deinitialize() {}
} // namespace OrpheusServer

#else

#include "common/Threading.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
	std::atomic<bool> s_running{false};
	std::thread s_thread;
	int s_listen_fd = -1;
	int s_port = 0;

	// ---- formatting helpers ----
	std::string hex32(u32 v)
	{
		char b[11];
		std::snprintf(b, sizeof(b), "0x%08x", v);
		return b;
	}
	std::string hex128(const u128& v)
	{
		char b[35];
		std::snprintf(b, sizeof(b), "0x%016llx%016llx",
			(unsigned long long)v.hi, (unsigned long long)v.lo);
		return b;
	}

	// ---- request helpers ----
	DebugInterface* cpuFromQuery(const std::string& query)
	{
		if (query.find("cpu=iop") != std::string::npos)
			return &r3000Debug;
		return &r5900Debug; // default: EE
	}
	std::string queryParam(const std::string& query, const std::string& key)
	{
		const std::string needle = key + "=";
		size_t p = query.find(needle);
		if (p == std::string::npos)
			return std::string();
		p += needle.size();
		size_t e = query.find('&', p);
		return query.substr(p, (e == std::string::npos) ? std::string::npos : e - p);
	}
	u32 parseU32(const std::string& s)
	{
		if (s.empty())
			return 0;
		return (u32)std::strtoul(s.c_str(), nullptr, 0); // accepts 0x-prefixed
	}

	// ---- endpoints (direct reads) ----
	std::string jsonStatus()
	{
		const bool vm = VMManager::HasValidVM();
		std::ostringstream o;
		o << "{\"vm\":" << (vm ? "true" : "false");
		if (vm)
		{
			o << ",\"paused\":" << (r5900Debug.isCpuPaused() ? "true" : "false")
			  << ",\"ee_pc\":\"" << hex32(r5900Debug.getPC()) << "\""
			  << ",\"iop_pc\":\"" << hex32(r3000Debug.getPC()) << "\""
			  << ",\"ee_cycles\":" << r5900Debug.getCycles();
		}
		o << "}";
		return o.str();
	}

	std::string jsonRegisters(DebugInterface* cpu)
	{
		if (!VMManager::HasValidVM())
			return "{\"error\":\"no vm\"}";

		std::ostringstream o;
		o << "{\"cpu\":\"" << DebugInterface::cpuName(cpu->getCpuType()) << "\","
		  << "\"pc\":\"" << hex32(cpu->getPC()) << "\",\"categories\":{";
		const int cats = cpu->getRegisterCategoryCount();
		for (int c = 0; c < cats; c++)
		{
			if (c)
				o << ",";
			o << "\"" << cpu->getRegisterCategoryName(c) << "\":{";
			const int n = cpu->getRegisterCount(c);
			for (int i = 0; i < n; i++)
			{
				if (i)
					o << ",";
				o << "\"" << cpu->getRegisterName(c, i) << "\":\""
				  << hex128(cpu->getRegister(c, i)) << "\"";
			}
			o << "}";
		}
		o << "}}";
		return o.str();
	}

	std::string jsonMemory(DebugInterface* cpu, u32 addr, u32 len)
	{
		if (!VMManager::HasValidVM())
			return "{\"error\":\"no vm\"}";
		if (len == 0)
			len = 16;
		if (len > 65536)
			len = 65536; // cap a single request

		std::vector<u8> buf(len);
		const bool ok = cpu->ReadBytes(addr, buf.data(), len);

		static const char* H = "0123456789abcdef";
		std::string hx;
		hx.reserve((size_t)len * 2);
		for (u32 i = 0; i < len; i++)
		{
			hx.push_back(H[buf[i] >> 4]);
			hx.push_back(H[buf[i] & 0xf]);
		}

		std::ostringstream o;
		o << "{\"addr\":\"" << hex32(addr) << "\",\"len\":" << len
		  << ",\"ok\":" << (ok ? "true" : "false") << ",\"hex\":\"" << hx << "\"}";
		return o.str();
	}

	// ---- control / mutation endpoints ----
	// Mutations run on the CPU thread fire-and-forget (block=false): the server
	// thread never waits on the CPU thread, so there is no shutdown deadlock.
	// The effect is observable via the read endpoints (/status, /breakpoints,
	// /watchpoints).
	BreakPointCpu bpCpuFromQuery(const std::string& query)
	{
		return (query.find("cpu=iop") != std::string::npos) ? BREAKPOINT_IOP : BREAKPOINT_EE;
	}

	std::string doPauseResume(bool pause)
	{
		if (!VMManager::HasValidVM())
			return "{\"error\":\"no vm\"}";
		Host::RunOnCPUThread([pause]() {
			if (pause)
				r5900Debug.pauseCpu();
			else
				r5900Debug.resumeCpu();
		}, false);
		return "{\"ok\":true}";
	}

	std::string addBreakpoint(const std::string& query)
	{
		if (!VMManager::HasValidVM())
			return "{\"error\":\"no vm\"}";
		const BreakPointCpu cpu = bpCpuFromQuery(query);
		const u32 addr = parseU32(queryParam(query, "addr"));
		if (addr == 0)
			return "{\"error\":\"addr required\"}";
		Host::RunOnCPUThread([cpu, addr]() {
			CBreakPoints::AddBreakPoint(cpu, addr);
			CBreakPoints::Update(cpu);
		}, false);
		return "{\"ok\":true}";
	}

	std::string removeBreakpoint(const std::string& query)
	{
		if (!VMManager::HasValidVM())
			return "{\"error\":\"no vm\"}";
		const BreakPointCpu cpu = bpCpuFromQuery(query);
		const u32 addr = parseU32(queryParam(query, "addr"));
		Host::RunOnCPUThread([cpu, addr]() {
			CBreakPoints::RemoveBreakPoint(cpu, addr);
			CBreakPoints::Update(cpu);
		}, false);
		return "{\"ok\":true}";
	}

	std::string listBreakpoints(const std::string& query)
	{
		const BreakPointCpu cpu = bpCpuFromQuery(query);
		const std::vector<BreakPoint> bps = CBreakPoints::GetBreakpoints(cpu, false);
		std::ostringstream o;
		o << "[";
		for (size_t i = 0; i < bps.size(); i++)
		{
			if (i)
				o << ",";
			o << "{\"addr\":\"" << hex32(bps[i].addr) << "\",\"enabled\":"
			  << (bps[i].enabled ? "true" : "false") << "}";
		}
		o << "]";
		return o.str();
	}

	MemCheckCondition memCondFromQuery(const std::string& query)
	{
		const std::string c = queryParam(query, "cond");
		if (c == "r")
			return MEMCHECK_READ;
		if (c == "w")
			return MEMCHECK_WRITE;
		return MEMCHECK_READWRITE; // default
	}

	std::string addWatchpoint(const std::string& query)
	{
		if (!VMManager::HasValidVM())
			return "{\"error\":\"no vm\"}";
		const BreakPointCpu cpu = bpCpuFromQuery(query);
		const u32 start = parseU32(queryParam(query, "start"));
		u32 end = parseU32(queryParam(query, "end"));
		if (end <= start)
			end = start + 1;
		const MemCheckCondition cond = memCondFromQuery(query);
		// MEMCHECK_LOG: record accesses (hits, lastPC/addr/size) without breaking.
		Host::RunOnCPUThread([cpu, start, end, cond]() {
			CBreakPoints::AddMemCheck(cpu, start, end, cond, MEMCHECK_LOG);
		}, false);
		return "{\"ok\":true}";
	}

	std::string removeWatchpoint(const std::string& query)
	{
		if (!VMManager::HasValidVM())
			return "{\"error\":\"no vm\"}";
		const BreakPointCpu cpu = bpCpuFromQuery(query);
		const u32 start = parseU32(queryParam(query, "start"));
		const u32 end = parseU32(queryParam(query, "end"));
		Host::RunOnCPUThread([cpu, start, end]() {
			CBreakPoints::RemoveMemCheck(cpu, start, end);
		}, false);
		return "{\"ok\":true}";
	}

	std::string listWatchpoints(const std::string& query)
	{
		const BreakPointCpu cpu = bpCpuFromQuery(query);
		const std::vector<MemCheck> mcs = CBreakPoints::GetMemChecks(cpu);
		std::ostringstream o;
		o << "[";
		for (size_t i = 0; i < mcs.size(); i++)
		{
			const MemCheck& m = mcs[i];
			if (i)
				o << ",";
			o << "{\"start\":\"" << hex32(m.start) << "\",\"end\":\"" << hex32(m.end) << "\","
			  << "\"cond\":" << (int)m.memCond << ",\"hits\":" << m.numHits
			  << ",\"lastPC\":\"" << hex32(m.lastPC) << "\",\"lastAddr\":\"" << hex32(m.lastAddr)
			  << "\",\"lastSize\":" << m.lastSize << "}";
		}
		o << "]";
		return o.str();
	}

	// ---- HTTP ----
	void sendResponse(int fd, int code, const std::string& body)
	{
		std::ostringstream o;
		o << "HTTP/1.1 " << code << (code == 200 ? " OK" : " Error") << "\r\n"
		  << "Content-Type: application/json\r\n"
		  << "Content-Length: " << body.size() << "\r\n"
		  << "Connection: close\r\n\r\n"
		  << body;
		const std::string resp = o.str();
		::send(fd, resp.data(), resp.size(), 0);
	}

	void handleClient(int fd)
	{
		// Read request headers (our endpoints are GET, no body).
		std::string req;
		char buf[2048];
		for (int i = 0; i < 16; i++)
		{
			const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
			if (n <= 0)
				break;
			req.append(buf, (size_t)n);
			if (req.find("\r\n\r\n") != std::string::npos)
				break;
		}

		std::string method, target;
		{
			std::istringstream ls(req);
			ls >> method >> target;
		}
		std::string path = target, query;
		const size_t qp = target.find('?');
		if (qp != std::string::npos)
		{
			path = target.substr(0, qp);
			query = target.substr(qp + 1);
		}

		int code = 200;
		std::string body;
		if (method == "GET" && path == "/status")
			body = jsonStatus();
		else if (method == "GET" && path == "/registers")
			body = jsonRegisters(cpuFromQuery(query));
		else if (method == "GET" && path == "/memory")
			body = jsonMemory(cpuFromQuery(query), parseU32(queryParam(query, "addr")),
				parseU32(queryParam(query, "len")));
		else if (method == "POST" && path == "/pause")
			body = doPauseResume(true);
		else if (method == "POST" && path == "/resume")
			body = doPauseResume(false);
		else if (method == "GET" && path == "/breakpoints")
			body = listBreakpoints(query);
		else if (method == "POST" && path == "/breakpoints")
			body = addBreakpoint(query);
		else if (method == "DELETE" && path == "/breakpoints")
			body = removeBreakpoint(query);
		else if (method == "GET" && path == "/watchpoints")
			body = listWatchpoints(query);
		else if (method == "POST" && path == "/watchpoints")
			body = addWatchpoint(query);
		else if (method == "DELETE" && path == "/watchpoints")
			body = removeWatchpoint(query);
		else
		{
			code = 404;
			body = "{\"error\":\"not found\"}";
		}

		sendResponse(fd, code, body);
	}

	void mainLoop()
	{
		Threading::SetNameOfCurrentThread("Orpheus API");
		while (s_running.load())
		{
			sockaddr_in cli{};
			socklen_t cl = sizeof(cli);
			const int fd = ::accept(s_listen_fd, (sockaddr*)&cli, &cl);
			if (fd < 0)
			{
				if (!s_running.load())
					break;
				continue;
			}
			handleClient(fd);
			::close(fd);
		}
	}
} // namespace

namespace OrpheusServer
{
	bool IsInitialized()
	{
		return s_running.load();
	}
	int GetPort()
	{
		return s_port;
	}

	bool Initialize(int port)
	{
		if (s_running.load())
			Deinitialize();

		const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
		{
			Console.WriteLn(Color_Red, "Orpheus: cannot open socket! HTTP API disabled.");
			return false;
		}
		int one = 1;
		::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons((u16)port);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only

		if (::bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0)
		{
			Console.WriteLn(Color_Red, "Orpheus: cannot bind socket! HTTP API disabled.");
			::close(fd);
			return false;
		}
		if (::listen(fd, 8) < 0)
		{
			::close(fd);
			return false;
		}

		s_listen_fd = fd;
		s_port = port;
		s_running.store(true);
		s_thread = std::thread(mainLoop);

		Console.WriteLn(Color_Green,
			("Orpheus: HTTP API listening on 127.0.0.1:" + std::to_string(port)).c_str());
		return true;
	}

	void Deinitialize()
	{
		if (!s_running.exchange(false))
			return;
		if (s_listen_fd >= 0)
		{
			::shutdown(s_listen_fd, SHUT_RDWR); // unblock accept()
			::close(s_listen_fd);
			s_listen_fd = -1;
		}
		if (s_thread.joinable())
			s_thread.join();
	}
} // namespace OrpheusServer

#endif // _WIN32
