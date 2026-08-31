"""tsf-anonymizer — strip customer-identifying data from PAN-OS tech support files.

Two halves, deliberately independent of each other:

* :mod:`tsf_anonymizer.core` rewrites the archive with consistent pseudonyms
  (same original value → same fake everywhere, so correlation survives).
* :mod:`tsf_anonymizer.compare` reads the original and the anonymized archive
  back and checks that *every* difference is explained by the mapping, that
  nothing identifying survived, and that the structure the debugging tools
  rely on (line counts, timestamps, counters, XML tree, binary payloads) is
  intact.
"""

from .core import Anonymizer, AnonymizeReport, anonymize_tsf  # noqa: F401
from .compare import CompareReport, compare_archives, compare_trees  # noqa: F401

__version__ = "0.2.0"
