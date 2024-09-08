import asyncio
import ipaddress
from colored import fg, attr
import os
import subprocess
import httpx
import psutil
import pandas as pd
import sys
from concurrent.futures import ThreadPoolExecutor
import time
from threading import Thread
import pyperclip
from tqdm import tqdm
import re
import configparser
import signal

config = configparser.ConfigParser()
if getattr(sys, 'frozen', False):
    datadir = os.path.dirname(sys.executable)
else:
    datadir = os.path.dirname(__file__)
IP_FILE = os.path.join(datadir, "ip.txt")
RESULT_FILE = os.path.join(datadir, "result.csv")
setting_path = os.path.join(datadir, "setting.conf")

PORTS = []
warp_process = None

async def read_ip_ranges():
    ip_ranges = ["162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24"]
    return ip_ranges

def ip_range_to_list(ip_range):
    return [str(ip) for ip in ipaddress.ip_network(ip_range, strict=False).hosts()]

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

async def get_public_ip(proxy=None):
    url = "https://api.ipify.org/?format=json"
    async with httpx.AsyncClient(proxies=proxy, timeout=10.0, http2=True) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json().get("ip")
        except httpx.RequestError:
            return None

def run_warp_plus(ip, portw, port):
    warp = os.path.join(datadir, "warp-plus.exe")
    os.chdir(datadir)
    cmd = [warp, "-e", f"{ip}:{portw}", "-b", f"127.0.0.1:{port}", "-4"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if process.stdout:
        try:
            for line in iter(process.stdout.readline, ''):
                if "serving proxy" in line:
                    return process
        except Exception:
            process.kill()
    return None

def terminate_process(process):
    if process is not None:
        try:
            psutil.Process(process.pid).terminate()
        except psutil.NoSuchProcess:
            pass

async def test_warp_plus(i, original_ip, ip, portw, port, executor):
    loop = asyncio.get_event_loop()
    process = None
    start_time = time.time()
    try:
        process = await asyncio.wait_for(loop.run_in_executor(executor, run_warp_plus, ip, portw, port), timeout=12)
        if process:
            try:
                new_ip = await asyncio.wait_for(get_public_ip(f"http://127.0.0.1:{port}"), timeout=10)
            except asyncio.TimeoutError:
                new_ip = None

            if new_ip and new_ip != original_ip:
                result = f"{fg(15)}IP: {fg(163)}{ip}:{portw}{fg(15)} | {fg(56)}warp-plus Test: {fg(70)}PASS{attr(0)} | {fg(208)}Warp IP: {fg(70)}{new_ip}{attr(0)}"
                success = True
            else:
                result = f"{fg(15)}IP: {fg(163)}{ip}:{portw}{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed{attr(0)}"
                success = False

            process.terminate()
            process.communicate()
        else:
            result = f"{fg(15)}IP: {fg(163)}{ip}:{portw}{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed{attr(0)}"
            success = False
    except asyncio.TimeoutError:
        result = f"{fg(15)}IP: {fg(163)}{ip}:{portw}{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed{attr(0)}"
        success = False
    finally:
        terminate_process(process)
    return result, success, time.time() - start_time

def run_warp_scanner(ip_count, pbar):
    warp_scanner = os.path.join(datadir, "warp-scaner.exe")
    os.chdir(datadir)
    cmd = [warp_scanner, "-file", IP_FILE, "-output", RESULT_FILE, "-max", "500"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')

    def read_stream(stream, callback):
        for line in iter(stream.readline, ''):
            if line:
                try:
                    callback(line.strip())
                except UnicodeDecodeError:
                    continue
        stream.close()

    def print_line(line):
        if '数据包丢失' in line or '收到UDP响应' in line:
            pbar.update(1)

    stdout_thread = Thread(target=read_stream, args=(process.stdout, print_line))
    stderr_thread = Thread(target=read_stream, args=(process.stderr, print_line))

    stdout_thread.start()
    stderr_thread.start()

    stdout_thread.join()
    stderr_thread.join()
    process.wait()
    os.remove(IP_FILE)

def read_warp_scanner_results():
    if os.path.exists(RESULT_FILE):
        df = pd.read_csv(RESULT_FILE, encoding='utf-8')
        os.remove(RESULT_FILE)
        ips = df.iloc[:, 0].tolist()
        pings = df.iloc[:, 2].tolist()
        return [(ip, ping) for ip, ping in zip(ips, pings)][:20]
    return []

async def scan_ips():
    original_ip = await get_public_ip()
    ip_ranges = await read_ip_ranges()
    while True:
        ip_count = 0
        print(f"{fg(2)}Scanning Endpoints...{attr(0)}\n")
        with open(IP_FILE, 'w', encoding="UTF-8") as f:
            for ip_range in ip_ranges:
                for ip in ip_range_to_list(ip_range):
                    f.write(ip + '\n')
                    ip_count += 1

        with tqdm(total=ip_count * 20, desc="Warp Scanner", unit="ip") as pbar:
            await asyncio.get_event_loop().run_in_executor(None, run_warp_scanner, ip_count * 20, pbar)

        warp_scanner_ips = read_warp_scanner_results()

        clear_console()

        I_P = {}
        results = [(ip.split(":")[0], float(ping.replace(" ms", "").replace("timeout", "inf"))) for ip, ping in warp_scanner_ips]
        for ip, ping in warp_scanner_ips:
            port = ip.split(":")[1]
            I_P[ip.split(":")[0]] = port
            if not int(port) in PORTS:
                PORTS.append(port)
        results.sort(key=lambda x: x[1])
        top_20 = results[:20]

        clear_console()
        for count, (ip, avg_ping_time) in enumerate(top_20, 1):
            if avg_ping_time != float('inf'):
                if avg_ping_time < 180:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(70) + f"{avg_ping_time:.2f}ms" + attr(0))
                elif avg_ping_time < 250:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(208) + f"{avg_ping_time:.2f}ms" + attr(0))
                else:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(160) + f"{avg_ping_time:.2f}ms" + attr(0))

        sys.stdout.write(f"\n{fg(70)}Testing ON Warp-plus... [13s]{attr(0)}")
        sys.stdout.flush()

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=20) as executor:
            all_failed = True
            test_tasks = [
                test_warp_plus(i, original_ip, ip, I_P[ip], 8086 + i, executor)
                for i, (ip, ping_time) in enumerate(top_20)
            ]

            countdown_task = asyncio.create_task(countdown(13))
            test_results = await asyncio.gather(*test_tasks)
            await countdown_task
            print("\r" + " " * 100 + "\r" + fg(70) + "Warp-plus Test [Done]\n" + attr(0))

            successful_results = [(result, success, duration) for result, success, duration in test_results]
            successful_results.sort(key=lambda x: (not x[1], x[2]))

            for i, (result, success, duration) in enumerate(successful_results[:10]):
                print(f"[{i + 1}] {result} | Duration: {duration:.2f}s")

            os.system("taskkill /f /im warp-plus.exe >nul 2>&1")

            if any(success for _, success, _ in successful_results):
                best_result = successful_results[0]
                best_result_str = best_result[0]
                best_ip_port = best_result_str.split("IP: ")[1].split(" | ")[0]
                best_ip, best_port = best_ip_port.split(":")
                for ip, ping in top_20:
                    if str(ip).replace("\r", "").replace("\n", "").replace(" ", "").replace(fg(163), "").replace(attr(0), "") == best_ip.replace("\r", "").replace("\n", "").replace(" ", "").replace(fg(163), "").replace(attr(0), ""):
                        best_ping = ping
                        best_duration = best_result[2]
                        IP = str(ip).replace("\r", "").replace("\n", "").replace(" ", "").replace(fg(163), "").replace(attr(0), "")
                        PRTT = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', str(best_port))
                        pyperclip.copy(f"{IP}:{PRTT}")
                        print(fg(56) + f"\nBest IP: {fg(163)}{best_ip}:{best_port}{attr(0)} | Duration: {best_duration:.2f}s | " + fg(56) + "Ping: " + fg(70) +  f"{best_ping:.2f}ms" + attr(0))
                        print(f"\n{fg(70)}IP:PORT Copied to Clipboard!{attr(0)}")
                        break
                print(f"\n{fg(70)}Scanning Completed!{attr(0)}")
                config.read(setting_path)
                config['settings']['ip'] = f'{IP}:{PRTT}'
                with open(setting_path, 'w') as configfile:
                    config.write(configfile)
                break
    return

async def scan_and_quick_connect():
    original_ip = await get_public_ip()
    ip_ranges = await read_ip_ranges()
    while True:
        print(f"{fg(2)}Scanning Endpoints...{attr(0)}\n")
        ip_count = 0
        with open(IP_FILE, 'w', encoding="UTF-8") as f:
            for ip_range in ip_ranges:
                for ip in ip_range_to_list(ip_range):
                    f.write(ip + '\n')
                    ip_count += 1

        with tqdm(total=ip_count * 20, desc="Warp Scanner", unit="ip") as pbar:
            await asyncio.get_event_loop().run_in_executor(None, run_warp_scanner, ip_count * 20, pbar)

        warp_scanner_ips = read_warp_scanner_results()

        clear_console()

        I_P = {}
        results = [(ip.split(":")[0], float(ping.replace(" ms", "").replace("timeout", "inf"))) for ip, ping in warp_scanner_ips]
        for ip, ping in warp_scanner_ips:
            port = ip.split(":")[1]
            I_P[ip.split(":")[0]] = port
            if not int(port) in PORTS:
                PORTS.append(port)
        results.sort(key=lambda x: x[1])
        top_20 = results[:20]

        clear_console()
        for count, (ip, avg_ping_time) in enumerate(top_20, 1):
            if avg_ping_time != float('inf'):
                if avg_ping_time < 180:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(70) + f"{avg_ping_time:.2f}ms" + attr(0))
                elif avg_ping_time < 250:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(208) + f"{avg_ping_time:.2f}ms" + attr(0))
                else:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(160) + f"{avg_ping_time:.2f}ms" + attr(0))

        sys.stdout.write(f"\n{fg(70)}Testing ON Warp-plus... [13s]{attr(0)}")
        sys.stdout.flush()

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=20) as executor:
            all_failed = True
            test_tasks = [
                test_warp_plus(i, original_ip, ip, I_P[ip], 8086 + i, executor)
                for i, (ip, ping_time) in enumerate(top_20)
            ]

            countdown_task = asyncio.create_task(countdown(13))
            test_results = await asyncio.gather(*test_tasks)
            await countdown_task
            print("\r" + " " * 100 + "\r" + fg(70) + "Warp-plus Test [Done]\n" + attr(0))

            successful_results = [(result, success, duration) for result, success, duration in test_results]
            successful_results.sort(key=lambda x: (not x[1], x[2]))

            for i, (result, success, duration) in enumerate(successful_results[:10]):
                print(f"[{i + 1}] {result} | Duration: {duration:.2f}s")

            os.system("taskkill /f /im warp-plus.exe >nul 2>&1")

            if any(success for _, success, _ in successful_results):
                best_result = successful_results[0]
                best_result_str = best_result[0]
                best_ip_port = best_result_str.split("IP: ")[1].split(" | ")[0]
                best_ip, best_port = best_ip_port.split(":")
                print(best_ip, best_port)
                for ip, ping in top_20:
                    if str(ip).replace("\r", "").replace("\n", "").replace(" ", "").replace(fg(163), "").replace(attr(0), "") == best_ip.replace("\r", "").replace("\n", "").replace(" ", "").replace(fg(163), "").replace(attr(0), ""):
                        best_ping = ping
                        best_duration = best_result[2]
                        IP = str(ip).replace("\r", "").replace("\n", "").replace(" ", "").replace(fg(163), "").replace(attr(0), "")
                        PRTT = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', str(best_port))
                        pyperclip.copy(f"{IP}:{PRTT}")
                        print(fg(56) + f"\nBest IP: {fg(163)}{best_ip}:{best_port}{attr(0)} | Duration: {best_duration:.2f}s | " + fg(56) + "Ping: " + fg(70) +  f"{best_ping:.2f}ms" + attr(0))
                        print(f"\n{fg(70)}IP:PORT Copied to Clipboard!{attr(0)}")
                        break
                print(f"\n{fg(70)}Scanning Completed!{attr(0)}")

                config.read(setting_path)
                config['settings']['ip'] = f'{IP}:{PRTT}'
                with open(setting_path, 'w') as configfile:
                    config.write(configfile)
                break

    await quick_connect(IP, PRTT)

async def scan_and_quick_connect_proxy():
    original_ip = await get_public_ip()
    ip_ranges = await read_ip_ranges()
    while True:
        print(f"{fg(2)}Scanning Endpoints...{attr(0)}\n")
        ip_count = 0
        with open(IP_FILE, 'w', encoding="UTF-8") as f:
            for ip_range in ip_ranges:
                for ip in ip_range_to_list(ip_range):
                    f.write(ip + '\n')
                    ip_count += 1

        with tqdm(total=ip_count * 20, desc="Warp Scanner", unit="ip") as pbar:
            await asyncio.get_event_loop().run_in_executor(None, run_warp_scanner, ip_count * 20, pbar)

        warp_scanner_ips = read_warp_scanner_results()

        clear_console()

        I_P = {}
        results = [(ip.split(":")[0], float(ping.replace(" ms", "").replace("timeout", "inf"))) for ip, ping in warp_scanner_ips]
        for ip, ping in warp_scanner_ips:
            port = ip.split(":")[1]
            I_P[ip.split(":")[0]] = port
            if not int(port) in PORTS:
                PORTS.append(port)
        results.sort(key=lambda x: x[1])
        top_20 = results[:20]

        clear_console()
        for count, (ip, avg_ping_time) in enumerate(top_20, 1):
            if avg_ping_time != float('inf'):
                if avg_ping_time < 180:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(70) + f"{avg_ping_time:.2f}ms" + attr(0))
                elif avg_ping_time < 250:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(208) + f"{avg_ping_time:.2f}ms" + attr(0))
                else:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(160) + f"{avg_ping_time:.2f}ms" + attr(0))

        sys.stdout.write(f"\n{fg(70)}Testing ON Warp-plus... [13s]{attr(0)}")
        sys.stdout.flush()

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=20) as executor:
            all_failed = True
            test_tasks = [
                test_warp_plus(i, original_ip, ip, I_P[ip], 8086 + i, executor)
                for i, (ip, ping_time) in enumerate(top_20)
            ]

            countdown_task = asyncio.create_task(countdown(13))
            test_results = await asyncio.gather(*test_tasks)
            await countdown_task
            print("\r" + " " * 100 + "\r" + fg(70) + "Warp-plus Test [Done]\n" + attr(0))

            successful_results = [(result, success, duration) for result, success, duration in test_results]
            successful_results.sort(key=lambda x: (not x[1], x[2]))

            for i, (result, success, duration) in enumerate(successful_results[:10]):
                print(f"[{i + 1}] {result} | Duration: {duration:.2f}s")

            os.system("taskkill /f /im warp-plus.exe >nul 2>&1")

            if any(success for _, success, _ in successful_results):
                best_result = successful_results[0]
                best_result_str = best_result[0]
                best_ip_port = best_result_str.split("IP: ")[1].split(" | ")[0]
                best_ip, best_port = best_ip_port.split(":")
                print(best_ip, best_port)
                for ip, ping in top_20:
                    if str(ip).replace("\r", "").replace("\n", "").replace(" ", "").replace(fg(163), "").replace(attr(0), "") == best_ip.replace("\r", "").replace("\n", "").replace(" ", "").replace(fg(163), "").replace(attr(0), ""):
                        best_ping = ping
                        best_duration = best_result[2]
                        IP = str(ip).replace("\r", "").replace("\n", "").replace(" ", "").replace(fg(163), "").replace(attr(0), "")
                        PRTT = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', str(best_port))
                        pyperclip.copy(f"{IP}:{PRTT}")
                        print(fg(56) + f"\nBest IP: {fg(163)}{best_ip}:{best_port}{attr(0)} | Duration: {best_duration:.2f}s | " + fg(56) + "Ping: " + fg(70) +  f"{best_ping:.2f}ms" + attr(0))
                        print(f"\n{fg(70)}IP:PORT Copied to Clipboard!{attr(0)}")
                        break
                print(f"\n{fg(70)}Scanning Completed!{attr(0)}")

                config.read(setting_path)
                config['settings']['ip'] = f'{IP}:{PRTT}'
                with open(setting_path, 'w') as configfile:
                    config.write(configfile)
                break

    await quick_connect_proxy(IP, PRTT)

async def scan_and_quick_connect_expermentall():
    original_ip = await get_public_ip()
    ip_ranges = await read_ip_ranges()
    while True:
        print(f"{fg(2)}Scanning Endpoints...{attr(0)}\n")
        ip_count = 0
        with open(IP_FILE, 'w', encoding="UTF-8") as f:
            for ip_range in ip_ranges:
                for ip in ip_range_to_list(ip_range):
                    f.write(ip + '\n')
                    ip_count += 1

        with tqdm(total=ip_count * 20, desc="Warp Scanner", unit="ip") as pbar:
            await asyncio.get_event_loop().run_in_executor(None, run_warp_scanner, ip_count * 20, pbar)

        warp_scanner_ips = read_warp_scanner_results()

        clear_console()

        I_P = {}
        results = [(ip.split(":")[0], float(ping.replace(" ms", "").replace("timeout", "inf"))) for ip, ping in warp_scanner_ips]
        for ip, ping in warp_scanner_ips:
            port = ip.split(":")[1]
            I_P[ip.split(":")[0]] = port
            if not int(port) in PORTS:
                PORTS.append(port)
        results.sort(key=lambda x: x[1])
        top_20 = results[:20]

        clear_console()
        for count, (ip, avg_ping_time) in enumerate(top_20, 1):
            if avg_ping_time != float('inf'):
                if avg_ping_time < 180:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(70) + f"{avg_ping_time:.2f}ms" + attr(0))
                elif avg_ping_time < 250:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(208) + f"{avg_ping_time:.2f}ms" + attr(0))
                else:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(160) + f"{avg_ping_time:.2f}ms" + attr(0))
        IP , PRTT = top_20[0][0], I_P[top_20[0][0]]
        break

    await scan_and_quick_connect_expermental1(IP, PRTT)

async def scan_and_quick_connect_expermental1(ip=None, portw=None):
    config.read(setting_path)
    if not ip:
        ip = config['settings']['ip'].split(":")[0]
    if not portw:
        portw = config['settings']['ip'].split(":")[1]
    port = config['settings']['port']

    clear_console()
    print(f"{fg(208)}Quick Connecting to {ip}:{portw}...")
    print(f"{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")

    if getattr(sys, 'frozen', False):
        datadir = os.path.dirname(sys.executable)
    else:
        datadir = os.path.dirname(__file__)
    warp = os.path.join(datadir, "warp-plus.exe")
    os.chdir(datadir)
    cmd = [warp, "-e", f"{ip}:{portw}", "-b", f"127.0.0.1:{port}", "--gool", "-4", "--scan", "--tun-experimental", "-v"]

    global warp_process
    warp_process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            line = await warp_process.stdout.readline()
            if "msg=\"serving tun\" interface=warp0" in line.decode():
                clear_console()
                print(f"{fg(70)}🚀 Connected.\n{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")
                await warp_process.wait()
                break
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    finally:
        os.system("taskkill /f /im warp-plus.exe >nul 2>&1")
        terminate_process(warp_process)

async def scan_and_quick_connect_expermentall_proxy():
    original_ip = await get_public_ip()
    ip_ranges = await read_ip_ranges()
    while True:
        print(f"{fg(2)}Scanning Endpoints...{attr(0)}\n")
        ip_count = 0
        with open(IP_FILE, 'w', encoding="UTF-8") as f:
            for ip_range in ip_ranges:
                for ip in ip_range_to_list(ip_range):
                    f.write(ip + '\n')
                    ip_count += 1

        with tqdm(total=ip_count * 20, desc="Warp Scanner", unit="ip") as pbar:
            await asyncio.get_event_loop().run_in_executor(None, run_warp_scanner, ip_count * 20, pbar)

        warp_scanner_ips = read_warp_scanner_results()

        clear_console()

        I_P = {}
        results = [(ip.split(":")[0], float(ping.replace(" ms", "").replace("timeout", "inf"))) for ip, ping in warp_scanner_ips]
        for ip, ping in warp_scanner_ips:
            port = ip.split(":")[1]
            I_P[ip.split(":")[0]] = port
            if not int(port) in PORTS:
                PORTS.append(port)
        results.sort(key=lambda x: x[1])
        top_20 = results[:20]

        clear_console()
        for count, (ip, avg_ping_time) in enumerate(top_20, 1):
            if avg_ping_time != float('inf'):
                if avg_ping_time < 180:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(70) + f"{avg_ping_time:.2f}ms" + attr(0))
                elif avg_ping_time < 250:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(208) + f"{avg_ping_time:.2f}ms" + attr(0))
                else:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(160) + f"{avg_ping_time:.2f}ms" + attr(0))
        IP , PRTT = top_20[0][0], I_P[top_20[0][0]]
        break

    await scan_and_quick_connect_expermental1_Proxy(IP, PRTT)

async def scan_and_quick_connect_expermental1_Proxy(ip=None, portw=None):
    config.read(setting_path)
    if not ip:
        ip = config['settings']['ip'].split(":")[0]
    if not portw:
        portw = config['settings']['ip'].split(":")[1]
    port = config['settings']['port']

    clear_console()
    print(f"{fg(208)}Quick Connecting to {ip}:{portw}...")
    print(f"{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")

    if getattr(sys, 'frozen', False):
        datadir = os.path.dirname(sys.executable)
    else:
        datadir = os.path.dirname(__file__)
    warp = os.path.join(datadir, "warp-plus.exe")
    os.chdir(datadir)
    cmd = [warp, "-e", f"{ip}:{portw}", "-b", f"127.0.0.1:{port}", "--gool", "-4", "--scan", "-v"]

    global warp_process
    warp_process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            line = await warp_process.stdout.readline()
            if "msg=\"serving proxy\" address=127.0.0.1" in line.decode():
                clear_console()
                print(f"{fg(70)}🚀 Connected.\n\nProxy: socks5\nip: 127.0.0.1\nport: {port}\n\n{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")
                await warp_process.wait()
                break
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    finally:
        os.system("taskkill /f /im warp-plus.exe >nul 2>&1")
        terminate_process(warp_process)

async def scan_and_quick_connect_expermental(ip=None, portw=None):
    config.read(setting_path)
    if not ip:
        ip = config['settings']['ip'].split(":")[0]
    if not portw:
        portw = config['settings']['ip'].split(":")[1]
    port = config['settings']['port']

    clear_console()
    print(f"{fg(208)}Quick Connecting to engage.cloudflareclient.com:2408...")
    print(f"{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")

    if getattr(sys, 'frozen', False):
        datadir = os.path.dirname(sys.executable)
    else:
        datadir = os.path.dirname(__file__)
    warp = os.path.join(datadir, "warp-plus.exe")
    os.chdir(datadir)
    cmd = [warp, "-e", f"engage.cloudflareclient.com:2408", "-b", f"127.0.0.1:{port}", "--gool", "-4", "--scan", "--tun-experimental"]

    global warp_process
    warp_process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            line = await warp_process.stdout.readline()
            if "msg=\"serving tun\" interface=warp0" in line.decode():
                clear_console()
                print(f"{fg(70)}🚀 Connected.\n{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")
                await warp_process.wait()
                break
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    finally:
        os.system("taskkill /f /im warp-plus.exe >nul 2>&1")
        terminate_process(warp_process)

async def scan_and_quick_connect_expermental_proxy(ip=None, portw=None):
    config.read(setting_path)
    if not ip:
        ip = config['settings']['ip'].split(":")[0]
    if not portw:
        portw = config['settings']['ip'].split(":")[1]
    port = config['settings']['port']

    clear_console()
    print(f"{fg(208)}Quick Connecting to engage.cloudflareclient.com:2408...")
    print(f"{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")

    if getattr(sys, 'frozen', False):
        datadir = os.path.dirname(sys.executable)
    else:
        datadir = os.path.dirname(__file__)
    warp = os.path.join(datadir, "warp-plus.exe")
    os.chdir(datadir)
    cmd = [warp, "-e", f"engage.cloudflareclient.com:2408", "-b", f"127.0.0.1:{port}", "--gool", "-4", "--scan"]

    global warp_process
    warp_process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            line = await warp_process.stdout.readline()
            if "msg=\"serving proxy\" address=127.0.0.1" in line.decode():
                clear_console()
                print(f"{fg(70)}🚀 Connected.\n\nProxy: socks5\nip: 127.0.0.1\nport: {port}\n\n{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")
                await warp_process.wait()
                break
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    finally:
        os.system("taskkill /f /im warp-plus.exe >nul 2>&1")
        terminate_process(warp_process)

async def quick_connect(ip=None, portw=None):
    config.read(setting_path)
    if not ip:
        ip = config['settings']['ip'].split(":")[0]
    if not portw:
        portw = config['settings']['ip'].split(":")[1]
    port = config['settings']['port']

    clear_console()
    print(f"{fg(208)}Quick Connecting to {ip}:{portw}...")
    print(f"{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")

    if getattr(sys, 'frozen', False):
        datadir = os.path.dirname(sys.executable)
    else:
        datadir = os.path.dirname(__file__)
    warp = os.path.join(datadir, "warp-plus.exe")
    os.chdir(datadir)
    cmd = [warp, "-e", f"{ip}:{portw}", "-b", f"127.0.0.1:{port}", "--gool", "-4", "--tun-experimental"]

    global warp_process
    warp_process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            line = await warp_process.stdout.readline()
            if "msg=\"serving tun\" interface=warp0" in line.decode():
                clear_console()
                print(f"{fg(70)}🚀 Connected.\n{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")
                await warp_process.wait()
                break
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    finally:
        await asyncio.sleep(0.1)
        os.system("taskkill /f /im warp-plus.exe >nul 2>&1")
        terminate_process(warp_process)

async def quick_connect_proxy(ip=None, portw=None):
    config.read(setting_path)
    if not ip:
        ip = config['settings']['ip'].split(":")[0]
    if not portw:
        portw = config['settings']['ip'].split(":")[1]
    port = config['settings']['port']

    clear_console()
    print(f"{fg(208)}Quick Connecting to {ip}:{portw}...")
    print(f"{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")

    if getattr(sys, 'frozen', False):
        datadir = os.path.dirname(sys.executable)
    else:
        datadir = os.path.dirname(__file__)
    warp = os.path.join(datadir, "warp-plus.exe")
    os.chdir(datadir)
    cmd = [warp, "-e", f"{ip}:{portw}", "-b", f"127.0.0.1:{port}", "--gool", "-4"]

    global warp_process
    warp_process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            line = await warp_process.stdout.readline()
            if "msg=\"serving proxy\" address=127.0.0.1" in line.decode():
                clear_console()
                print(f"{fg(70)}🚀 Connected.\n\nProxy: socks5\nip: 127.0.0.1\nport: {port}\n\n{fg(255)}Press {fg(1)}Ctrl+C{fg(255)} to disconnect and return to the main menu.{attr(0)}")
                await warp_process.wait()
                break
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    finally:
        await asyncio.sleep(0.1)
        os.system("taskkill /f /im warp-plus.exe >nul 2>&1")
        terminate_process(warp_process)

def signal_handler(sig, frame):
    print(f"{fg(160)}\nDisconnected. Returning to main menu...{attr(0)}")
    if warp_process:
        terminate_process(warp_process)
    loop = asyncio.get_event_loop()
    for task in asyncio.all_tasks(loop):
        task.cancel()
    asyncio.get_event_loop().stop()

async def handle_interrupt():
    print(f"{fg(160)}\nDisconnected. Returning to main menu...{attr(0)}")
    terminate_process(warp_process)
    for task in asyncio.all_tasks():
        task.cancel()
    await asyncio.gather(*asyncio.all_tasks(), return_exceptions=True)

async def countdown(seconds):
    for remaining in range(seconds, 0, -1):
        sys.stdout.write(f"\r{fg(70)}Testing ON Warp-plus... [{remaining}s] {attr(0)}")
        sys.stdout.flush()
        await asyncio.sleep(1)
    sys.stdout.write("\r")
    sys.stdout.flush()

async def main():
    while True:
        clear_console()
        print("---------------------[Tunnel Mode]----------------------------\n")
        print(f"{fg(255)}[1] {fg(40)}Quick Connect (Tun Mode)")
        print(f"{fg(255)}[2] {fg(208)}Scan {fg(255)}And {fg(40)}Quick Connect (Scan endpoint + Tun Mode)")
        print(f"{fg(255)}[3] {fg(208)}Scan {fg(255)}And {fg(40)}Quick Connect {fg(255)}[Expermental] (Defult endpoint + warp scanner + Tun Mode)")
        print(f"{fg(255)}[4] {fg(208)}Scan {fg(255)}And {fg(40)}Quick Connect {fg(208)}[Expermental] (Scan endpoint + warp scanner + Tun Mode)\n")
        print(f"{fg(255)}---------------------[PROXY]----------------------------\n")
        print(f"{fg(255)}[5] {fg(40)}Quick Connect (Proxy Mode)")
        print(f"{fg(255)}[6] {fg(208)}Scan {fg(255)}And {fg(40)}Quick Connect (Scan endpoint + Proxy Mode)")
        print(f"{fg(255)}[7] {fg(208)}Scan {fg(255)}And {fg(40)}Quick Connect {fg(255)}[Expermental] (Defult endpoint + warp scanner + Proxy Mode)")
        print(f"{fg(255)}[8] {fg(208)}Scan {fg(255)}And {fg(40)}Quick Connect {fg(208)}[Expermental] (Scan endpoint + warp scanner + Proxy Mode)")
        print(f"\n{fg(255)}[9] {fg(208)}Scan Only (Scan endpoint)")
        print(f"\n{fg(255)}[0] {fg(1)}Exit{attr(0)}")

        choice = input("\nSelect an option: ")

        clear_console()
        try:
            if choice == "1":
                await quick_connect()
            elif choice == "2":
                await scan_and_quick_connect()
            elif choice == "3":
                await scan_and_quick_connect_expermental()
            elif choice == "4":
                await scan_and_quick_connect_expermentall()
            if choice == "5":
                await quick_connect_proxy()
            elif choice == "6":
                await scan_and_quick_connect_proxy()
            elif choice == "7":
                await scan_and_quick_connect_expermental_proxy()
            elif choice == "8":
                await scan_and_quick_connect_expermentall_proxy()
            elif choice == "9":
                await scan_ips()
            elif choice == "0":
                break
            else:
                print(f"{fg(160)}Invalid option, please try again.{attr(0)}")
            input("\nPress Enter to continue...")
        except asyncio.CancelledError:
            print(f"{fg(160)}Operation cancelled.{attr(0)}")

if __name__ == "__main__":
    clear_console()
    print(f"{fg(2)}Scanning Endpoints...{attr(0)}\n")

    try:
        if sys.version_info >= (3, 11):
            asyncio.run(main())
        else:
            loop = asyncio.get_event_loop()
            signal.signal(signal.SIGINT, signal_handler)
            try:
                loop.run_until_complete(main())
            except asyncio.CancelledError:
                pass
            finally:
                loop.run_until_complete(handle_interrupt())
                loop.close()
    except KeyboardInterrupt:
        print(f"{fg(160)}\nOperation cancelled by user. Exiting...{attr(0)}")
