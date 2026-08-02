import subprocess
import signal
import sys

zeek_process = None


def cleanup(signum=None, frame=None):
    global zeek_process

    print("\nStopping Zeek...")

    if zeek_process and zeek_process.poll() is None:
        zeek_process.terminate()

        try:
            zeek_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("Zeek did not stop gracefully. Killing it...")
            zeek_process.kill()

    print("Zeek stopped.")
    sys.exit(0)


def main():
    global zeek_process

    # Handle Ctrl+C and termination signals
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print("Starting Zeek...")
    print("Interface: en0")

    try:
        zeek_process = subprocess.Popen(
            ["sudo", "zeek", "-i", "en0", "-C"]
        )

        print(f"Zeek started with PID: {zeek_process.pid}")
        print("Zeek is now logging network traffic.")
        print("Press Ctrl+C to stop Zeek.")

        # Keep Python running while Zeek is running
        zeek_process.wait()

    except KeyboardInterrupt:
        cleanup()

    except Exception as e:
        print(f"Error: {e}")
        cleanup()


if __name__ == "__main__":
    main()