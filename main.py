import argparse
from extract import Extract


IDLE_TIME = 10
ACTIVE_TIME = 5


def main():
    parser = argparse.ArgumentParser(prog="MyFlowMeter")

    parser.add_argument("-s", "--source", required=True, help="Source filename")
    parser.add_argument("-o", "--output", required=True, help="Output filename")

    args = parser.parse_args()

    source_filename = args.source
    output_filename = args.output

    extractor = Extract(idle_time=IDLE_TIME, active_time=ACTIVE_TIME)
    extractor.process_file(source_filename)
    extractor.write_to_file(output_filename)


if __name__ == "__main__":
    main()