import psutil
import time

previous_disk_usage = psutil.disk_io_counters()
previous_io_stats = {}
last_update_time = time.time()

cpu_percent_data = []
disk_read_data = []
disk_write_data = []

def categorize_power_consumption(cpu_percent):
    """Categorize power consumption based on CPU percentage."""
    if cpu_percent > 50:
        return "Very High"
    elif cpu_percent > 20:
        return "High"
    elif cpu_percent > 10:
        return "Moderate"
    elif cpu_percent > 5:
        return "Low"
    else:
        return "Very Low"

def update_process_info():
    """Update process information such as CPU and disk usage."""
    global previous_disk_usage, previous_io_stats, last_update_time

    processes = []
    num_cores = psutil.cpu_count(logical=True)

    current_time = time.time()
    interval = current_time - last_update_time

    current_disk_usage = psutil.disk_io_counters()
    disk_read_rate = (current_disk_usage.read_bytes - previous_disk_usage.read_bytes) / (1024 * 1024 * interval)  # MB/s
    disk_write_rate = (current_disk_usage.write_bytes - previous_disk_usage.write_bytes) / (1024 * 1024 * interval)  # MB/s

    total_cpu_percent = psutil.cpu_percent(interval=1)

    total_read_rate = 0
    total_write_rate = 0

    previous_disk_usage = current_disk_usage
    last_update_time = current_time

    # Update data lists for graph plotting
    cpu_percent_data.append(total_cpu_percent)
    disk_read_data.append(disk_read_rate)
    disk_write_data.append(disk_write_rate)

    for proc in psutil.process_iter(['name']):
        try:
            process_name = proc.info['name']
            cpu_percent = proc.cpu_percent(interval=None) / num_cores

            if process_name == 'System Idle Process':
                continue

            io_counters = proc.io_counters()
            if io_counters:
                current_read = io_counters.read_bytes / (1024 * 1024)
                current_write = io_counters.write_bytes / (1024 * 1024)

                prev_read, prev_write = previous_io_stats.get(proc.pid, (current_read, current_write))
                read_rate = (current_read - prev_read) / interval
                write_rate = (current_write - prev_write) / interval

                previous_io_stats[proc.pid] = (current_read, current_write)

                total_read_rate += read_rate
                total_write_rate += write_rate
            else:
                read_rate = 0
                write_rate = 0

            power_consumption = categorize_power_consumption(cpu_percent)
            processes.append((process_name, cpu_percent, power_consumption, f"{read_rate:.2f} MB/s", f"{write_rate:.2f} MB/s"))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    processes.sort(key=lambda x: x[1], reverse=True)

    return processes, total_cpu_percent, total_read_rate, total_write_rate