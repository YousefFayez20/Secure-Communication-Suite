import hashlib


#256-bit, uncomputationally feasible.
def compute_sha256(data):
    """Generate SHA-256 hash of the given data."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data.encode())  # Convert data to bytes before hashing
    return sha256_hash.hexdigest()

def compute_md5(data):
    """Generate MD5 hash of the given data."""
    md5_hash = hashlib.md5()
    md5_hash.update(data.encode())  # Convert data to bytes before hashing
    return md5_hash.hexdigest()

#128-bit, It's possible to create two different inputs that produce the same hash.Finding an input that produces a specific hash is computationally feasible.


def verify_hash(data, given_hash, algorithm="sha256"):
    """Verify if the hash of the data matches the given hash."""
    if algorithm == "sha256":
        return compute_sha256(data) == given_hash
    elif algorithm == "md5":
        return compute_md5(data) == given_hash
    else:
        raise ValueError("Unsupported hashing algorithm. Use 'sha256' or 'md5'.")
