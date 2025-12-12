from src.services.dataset_loader import fulldataset



def main():
    for each in fulldataset.dataset:
        print(each)
    print(len(fulldataset.dataset))


if __name__ == "__main__":
    main()
