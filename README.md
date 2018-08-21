# tc-users

This is an eBPF classifier that maps a list of users to either MAC or IP
addresses. It's a work in progress.

# Installation

- Example for Ubuntu 18.04: `add-apt-repository "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe"`
- `apt-get install build-essential clang libc6-dev-i386`
- Might be needed for Debian: `apt-get install linux-headers-$(uname -r)`
- Before compiling tc-adv: `apt-get install pkg-config bison flex libcap-dev libmnl-dev libelf-dev`
- `make`

# Tasks

- For version 0.1 (i.e. usable):
  - Finish implementing flow fairness for users and unclassified flows
  - Improve output:
    - Warn on conflicting user ID mappings during classify
    - Print summary stats at end of each step, including time taken
    - Print logging in a standard way
    - If needed, support wrapped errors so as not to lose detail
    - Give more detailed error reporting for min and max flows per user
  - Get IPv6 working
  - Docs / man page
- For later:
  - Add subnet support with LPM trie
  - Minimize bpf map ops
  - Support VLAN tagged frames, IPIP tunneling and other encapsulations (rabbit hole)
  - Support tins (skb priority field)
