from sklearn.model_selection import train_test_split
def split_data(X, y, test_size=0.25, random_state=42):
    return train_test_split(X, y, test_size=test_size, random_state=random_state)
