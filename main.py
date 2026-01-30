import argparse
from extract import Extract

DEFAULT_IDLE_TIME = 10
DEFAULT_ACTIVE_TIME = 5


def load_config(filename):
    config = {}

    try:
        with open(filename, "r") as conf:
            for line in conf:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if "=" not in line:
                    continue

                key, value = line.split("=", 1)
                config[key.strip()] = value.strip()
    except FileNotFoundError:
        pass

    return config


def main():
    # load config file
    config = load_config("myflowmeter.conf")

    idle_time = int(config.get("IDLE_TIME", DEFAULT_IDLE_TIME))
    active_time = int(config.get("ACTIVE_TIME", DEFAULT_ACTIVE_TIME))

    parser = argparse.ArgumentParser(prog="MyFlowMeter")

    parser.add_argument("-s", "--source", type=str, required=True, help="Source filename")
    parser.add_argument("-o", "--output", type=str, required=True, help="Output filename")
    parser.add_argument("-l", "--label", type=str, required=True, help="Label of extracted flow")

    parser.add_argument("--idle-time", type=int, help="Idle time threshold (seconds)")
    parser.add_argument("--active-time", type=int, help="Active time threshold (seconds)")

    args = parser.parse_args()

    if args.idle_time is not None:
        idle_time = args.idle_time

    if args.active_time is not None:
        active_time = args.active_time
    
    label = "Normal"

    if args.label is not None:
        label = args.label

    extractor = Extract(idle_time=idle_time, active_time=active_time, label=label)
    extractor.process_file(args.source)
    extractor.write_to_file(args.output)


if __name__ == "__main__":
    main()
