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

PORTS = []
if getattr(sys, 'frozen', False):
    datadir = os.path.dirname(sys.executable)
else:
    datadir = os.path.dirname(__file__)
IP_FILE = os.path.join(datadir, "ip.txt")
RESULT_FILE = os.path.join(datadir, "result.csv")

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

def run_warp_plus(ip, port):
    warp = os.path.join(datadir, "warp-plus.exe")
    os.chdir(datadir)
    cmd = [warp, "-e", f"{ip}:{port}", "-b", f"127.0.0.1:{port}", "-4"]
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

async def test_warp_plus(i, original_ip, ip, port, executor):
    loop = asyncio.get_event_loop()
    process = None
    start_time = time.time()
    try:
        process = await asyncio.wait_for(loop.run_in_executor(executor, run_warp_plus, ip, port), timeout=12)
        if process:
            try:
                new_ip = await asyncio.wait_for(get_public_ip(f"http://127.0.0.1:{port}"), timeout=10)
            except asyncio.TimeoutError:
                new_ip = None

            if new_ip and new_ip != original_ip:
                result = f"{fg(15)}IP: {fg(163)}{ip}:{port}{fg(15)} | {fg(56)}warp-plus Test: {fg(70)}PASS{attr(0)} | {fg(208)}Warp IP: {fg(70)}{new_ip}{attr(0)}"
                success = True
            else:
                result = f"{fg(15)}IP: {fg(163)}{ip}:{port}{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed{attr(0)}"
                success = False

            process.terminate()
            process.communicate()
        else:
            result = f"{fg(15)}IP: {fg(163)}{ip}:{port}{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed{attr(0)}"
            success = False
    except asyncio.TimeoutError:
        result = f"{fg(15)}IP: {fg(163)}{ip}:{port}{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed{attr(0)}"
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

async def main():
    original_ip = await get_public_ip()
    ip_ranges = await read_ip_ranges()
    while True:
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
        print(f"{fg(2)}Scanning Endpoints...{attr(0)}\n")

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
                test_warp_plus(i, original_ip, ip, I_P[ip], executor)
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
                        PRTT = PRTT = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', str(best_port))
                        pyperclip.copy(f"{IP}:{PRTT}")
                        print(fg(56) + f"\nBest IP: {fg(163)}{best_ip}:{best_port}{attr(0)} | Duration: {best_duration:.2f}s | " + fg(56) + "Ping: " + fg(70) +  f"{best_ping:.2f}ms" + attr(0))
                        print(f"\n{fg(70)}IP:PORT Copied to Clipboard!{attr(0)}")
                        break
                print(f"\n{fg(70)}Scanning Completed!{attr(0)}")
                break
    input("\nPress Enter to exit...")

async def countdown(seconds):
    for remaining in range(seconds, 0, -1):
        sys.stdout.write(f"\r{fg(70)}Testing ON Warp-plus... [{remaining}s] {attr(0)}")
        sys.stdout.flush()
        await asyncio.sleep(1)
    sys.stdout.write("\r")
    sys.stdout.flush()

if __name__ == "__main__":
    clear_console()
    print(f"{fg(2)}Scanning Endpoints...{attr(0)}\n")

    if sys.version_info >= (3, 11):
        asyncio.run(main())
    else:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
