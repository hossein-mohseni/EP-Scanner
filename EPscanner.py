import asyncio
import ipaddress
import aioping
from colored import fg, attr
import os
import socket
import subprocess
import requests
from tqdm import tqdm
import sys
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
import time

async def read_ip_ranges():
    ip_ranges = ["162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24"]
    return ip_ranges

def ip_range_to_list(ip_range):
    ip_list = []
    network = ipaddress.ip_network(ip_range, strict=False)
    for ip in network.hosts():
        ip_list.append(str(ip))
    return ip_list

async def ping_ip(semaphore, ip, num_pings=3):
    async with semaphore:
        ping_times = []
        for _ in range(num_pings):
            try:
                delay = await aioping.ping(ip, timeout=1.0) * 1000
                ping_times.append(delay)
            except TimeoutError:
                ping_times.append(float('inf'))

        valid_pings = [ping for ping in ping_times if ping != float('inf')]
        if valid_pings:
            average_ping = sum(valid_pings) / len(valid_pings)
        else:
            average_ping = float('inf')

        return ip, average_ping

async def resolve_domain(domain):
    loop = asyncio.get_event_loop()
    try:
        return await loop.getaddrinfo(domain, None, family=socket.AF_INET)
    except socket.gaierror as e:
        return []

def clear_console():
    if os.name == 'nt':
        os.system('cls')
    # else:
    #     os.system('clear')

def get_public_ip(proxy=None):
    url = "https://api.ipify.org/?format=json"
    try:
        if proxy:
            response = requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=10)
        else:
            response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("ip")
    except requests.RequestException as e:
        return None

def run_warp_plus(ip):
    if getattr(sys, 'frozen', False):
        datadir = os.path.dirname(sys.executable)
    else:
        datadir = os.path.dirname(__file__)
    warp = os.path.join(datadir, "warp-plus.exe")
    os.chdir(datadir)
    cmd = [warp, "-e", f"{ip}:2408", "-b", "127.0.0.1:8086", "--gool", "-4"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if process.stdout:
        try:
            for line in iter(process.stdout.readline, ''):
                if "serving proxy" in line:
                    return process
        except Exception as e:
            process.kill()
    return None

async def test_warp_plus(i, original_ip, ip, executor):
    loop = asyncio.get_event_loop()
    process = None
    try:
        process = await asyncio.wait_for(loop.run_in_executor(executor, run_warp_plus, ip), timeout=20)
        if process:
            try:
                new_ip = await asyncio.wait_for(loop.run_in_executor(None, get_public_ip, "http://127.0.0.1:8086"), timeout=10)
            except asyncio.TimeoutError:
                new_ip = None

            if new_ip and new_ip != original_ip:
                result = f"{fg(15)}[{i + 1}] {fg(15)}- {fg(56)}IP: {fg(163)}{ip}:2408{fg(15)} | {fg(56)}warp-plus Test: {fg(70)}PASS{attr(0)}"
                success = True
            else:
                result = f"{fg(15)}[{i + 1}] {fg(15)}- {fg(56)}IP: {fg(163)}{ip}:2408{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed{attr(0)}"
                success = False

            process.terminate()
            process.communicate()
        else:
            result = f"{fg(15)}[{i + 1}] {fg(15)}- {fg(56)}IP: {fg(163)}{ip}:2408{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed{attr(0)}"
            success = False
    except asyncio.TimeoutError:
        result = f"{fg(15)}[{i + 1}] {fg(15)}- {fg(56)}IP: {fg(163)}{ip}:2408{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed{attr(0)}"
        success = False
        if process and process.poll() is None:
            process.terminate()
            process.communicate()
    except Exception as e:
        result = f"{fg(15)}[{i + 1}] {fg(15)}- {fg(56)}IP: {fg(163)}{ip}:2408{fg(15)} | {fg(56)}warp-plus Test: {fg(160)}Failed with error: {e}{attr(0)}"
        success = False
        if process and process.poll() is None:
            process.terminate()
            process.communicate()
    return result, success

async def main():
    original_ip = get_public_ip()
    ip_ranges = await read_ip_ranges()
    cpu_count = multiprocessing.cpu_count()
    semaphore_size = cpu_count * 10
    semaphore = asyncio.Semaphore(semaphore_size)

    while True:
        tasks = []

        for ip_range in ip_ranges:
            ip_list = ip_range_to_list(ip_range)
            for ip in ip_list:
                tasks.append(ping_ip(semaphore, ip))

        domain_ips = await resolve_domain("engage.cloudflareclient.com")
        for entry in domain_ips:
            ip = entry[4][0]
            tasks.append(ping_ip(semaphore, ip))

        results = []
        with tqdm(total=len(tasks), desc="Scanning", unit="ip", bar_format="{l_bar}{bar}| Remaining: {remaining}") as pbar:
            for f in asyncio.as_completed(tasks):
                result = await f
                results.append(result)
                pbar.update(1)

        results = sorted(results, key=lambda x: x[1])
        top_5 = results[:5]

        clear_console()

        count = 0
        for ip, avg_ping_time in top_5:
            if avg_ping_time != float('inf'):
                count += 1
                if avg_ping_time < 180:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(70) + f"{avg_ping_time:.2f}ms" + attr(0))
                elif avg_ping_time < 250:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(208) + f"{avg_ping_time:.2f}ms" + attr(0))
                else:
                    print(fg(15) + f"[{count}] " + fg(15) + "- " + fg(56) + "IP: " + fg(163) + f"{ip}" + fg(15) + " | " + fg(56) + "Ping: " + fg(160) + f"{avg_ping_time:.2f}ms" + attr(0))

        print(f"\n{fg(70)}Testing ON Warp-plus...{attr(0)}\n")

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as executor:
            all_failed = True
            for i, (ip, _) in enumerate(top_5):
                start_time = time.time()
                result, success = await test_warp_plus(i, original_ip, ip, executor)
                end_time = time.time()
                print(result)
                if success:
                    all_failed = False

            if not all_failed:
                break

    print(f"\n{fg(70)}Scanning Completed!{attr(0)}\n")
    input("Press Enter to exit...")

if __name__ == "__main__":
    clear_console()
    print(f"{fg(2)}Scanning Endpoints...{attr(0)}\n")
    asyncio.run(main())
