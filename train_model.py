import argparse
import json

from ml_model import train_and_save_model


def main():
    parser = argparse.ArgumentParser(description="Train the phishing email detection model.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Retrain the model even if a saved artifact already exists.",
    )
    args = parser.parse_args()

    artifact = train_and_save_model(force=args.force)

    print(
        json.dumps(
            {
                "trained_at": artifact["trained_at"],
                "training_rows": artifact["training_rows"],
                "feature_count": artifact["feature_count"],
                "threshold": artifact["threshold"],
                **artifact["metrics"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
