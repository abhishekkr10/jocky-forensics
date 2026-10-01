import os
import tempfile

# Configure isolation before application modules are imported during collection.
os.environ["JOCKY_DATA"] = tempfile.mkdtemp(prefix="jocky-tests-")
os.environ["JOCKY_KEY_PATH"] = os.path.join(tempfile.mkdtemp(prefix="jocky-test-keys-"), "checkpoint.key")
