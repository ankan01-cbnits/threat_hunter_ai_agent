from dotenv import load_dotenv
load_dotenv()

from app.tools.parse_logs import parse_all_logs


def main():
    print("Hello from threat-hunter!")
    something = parse_all_logs()
    print(something)


if __name__ == "__main__":
    main()
