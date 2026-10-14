# pickle auf User-Input (CWE-502, absichtlich verwundbar)
import pickle


def load_session(data: bytes):
    return pickle.loads(data)
