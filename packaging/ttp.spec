# ══════════════════════════════════════════════════════════════════════
# TTP — RPM Spec File
# ══════════════════════════════════════════════════════════════════════
#
# This is the recipe that rpmbuild uses to create the .rpm package.
# It defines what to build, how to build it, what files to include,
# and what scripts to run on install/uninstall.
#
# The @@VERSION@@ placeholder is replaced at build time by
# build_rpm.sh with the actual version from pyproject.toml.
#
# Key sections:
#   %build    - Compiles the Python wheel and SELinux policy from source
#   %install  - Places files into the package's fake filesystem
#   %post     - Runs after installation (loads SELinux module)
#   %preun    - Runs before removal (unloads SELinux module)
#   %files    - Lists every file the package owns
# ══════════════════════════════════════════════════════════════════════

Name:           ttp
Version:        @@VERSION@@
Release:        1%{?dist}
Summary:        Transparent Tor Proxy

License:        MIT
URL:            https://github.com/onyks-os/TransparentTorProxy
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  unzip
BuildRequires:  checkpolicy
Requires:       python3
Requires:       python3-typer
Requires:       python3-rich
Requires:       python3-stem
Requires:       nftables
Requires:       tor
Requires:       policycoreutils

%description
A Linux CLI tool that transparently routes all system traffic through the Tor network.

%prep
%autosetup

%build
# Ensure build module is available, then build the wheel
python3 -m pip install build --user || true
python3 -m build --wheel

# Compile SELinux policy
cd assets/selinux
checkmodule -M -m -o ttp_tor_policy.mod ttp_tor_policy.te
semodule_package -o ttp_tor_policy.pp -m ttp_tor_policy.mod
cd -

%install
# Unpack the wheel directly into the Python site-packages directory
mkdir -p %{buildroot}%{python3_sitelib}
unzip -q dist/ttp-*.whl -d %{buildroot}%{python3_sitelib}/

# Create the main executable script for the CLI
mkdir -p %{buildroot}%{_bindir}
cat << 'EOF' > %{buildroot}%{_bindir}/ttp
#!/usr/bin/python3
import sys
from ttp.cli import app
if __name__ == '__main__':
    sys.exit(app())
EOF
chmod +x %{buildroot}%{_bindir}/ttp

# Install systemd service
mkdir -p %{buildroot}%{_unitdir}
cp packaging/ttp.service %{buildroot}%{_unitdir}/

# Install SELinux policies so they are available for the %post scriptlet
mkdir -p %{buildroot}/opt/ttp/assets/selinux
cp assets/selinux/ttp_tor_policy.pp %{buildroot}/opt/ttp/assets/selinux/
cp assets/selinux/ttp_tor_policy.te %{buildroot}/opt/ttp/assets/selinux/

%post
%systemd_post ttp.service
# $1 == 1 means initial installation, not an upgrade
if [ "$1" -eq 1 ]; then
    echo "[TTP] Installing SELinux policy module..."
    semodule -i /opt/ttp/assets/selinux/ttp_tor_policy.pp || :
fi

%preun
%systemd_preun ttp.service
# $1 == 0 means package is being completely removed
if [ "$1" -eq 0 ]; then
    echo "[TTP] Removing SELinux policy module..."
    semodule -r ttp_tor_policy || :
fi

%postun
%systemd_postun_with_restart ttp.service

%files
%license LICENSE
%{_bindir}/ttp
%{python3_sitelib}/ttp/
%{python3_sitelib}/ttp-*.dist-info/
%{_unitdir}/ttp.service
%dir /opt/ttp
%dir /opt/ttp/assets
%dir /opt/ttp/assets/selinux
/opt/ttp/assets/selinux/ttp_tor_policy.pp
/opt/ttp/assets/selinux/ttp_tor_policy.te

%changelog
* Sun Apr 26 2026 onyks <ttp.nzkav@aleeas.com> - @@VERSION@@-1
- Initial native RPM package release
