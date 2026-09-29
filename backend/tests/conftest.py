import os
import tempfile

# Configure isolation before application modules are imported during collection.
os.environ["JOCKY_DATA"] = tempfile.mkdtemp(prefix="jocky-tests-")
