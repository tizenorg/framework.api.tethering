Name:       capi-network-tethering
Summary:    Tethering Framework
Version:    0.0.15
Release:    1
#VCS:        framework/api/tethering#capi-network-tethering-0.0.15-1-89-ge26cd7235d4a5eae37e95237630616beab704461
Group:      TO_BE/FILLED_IN
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%if %{_repository} == "wearable"
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(dbus-1)
BuildRequires: pkgconfig(dbus-glib-1)
BuildRequires: pkgconfig(capi-base-common)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(secure-storage)
BuildRequires: pkgconfig(libssl)
BuildRequires: cmake
%else
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(dbus-glib-1)
BuildRequires: pkgconfig(capi-base-common)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(vconf)
BuildRequires: cmake
%endif

%description
Tethering framework library for CAPI

%package devel
Summary:	Development package for Tethering framework library
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
%description devel
Development package for Tethering framework library

%prep
%setup -q

%build
%if %{_repository} == "wearable"
cd wearable
%ifarch %{arm}
%cmake . -DCMAKE_BUILD_TYPE="Private" -DARCH=arm
%else
%if 0%{?simulator}
%cmake . -DCMAKE_BUILD_TYPE="Private" -DARCH=emul
%else
%cmake . -DCMAKE_BUILD_TYPE="Private" -DARCH=i586
%endif
%endif
make %{?jobs:-j%jobs}
%else
cd mobile
%ifarch %{arm}
%cmake . -DARCH=arm
%else
%if 0%{?simulator}
%cmake . -DARCH=emul
%else
%cmake . -DARCH=i586
%endif
%endif
make %{?jobs:-j%jobs}
%endif

%install
%if %{_repository} == "wearable"
cd wearable
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/capi-network-tethering
#cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/capi-network-tethering-devel
%else
cd mobile
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/%{name}
%endif

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%if %{_repository} == "wearable"
%manifest wearable/capi-network-tethering.manifest
%else
%manifest mobile/capi-network-tethering.manifest
%endif
%defattr(-,root,root,-)
%{_libdir}/*.so.*
/usr/share/license/%{name}
%ifarch %{arm}
/etc/config/connectivity/sysinfo-tethering.xml
%else
%if 0%{?simulator}
# Noop
%else
/etc/config/connectivity/sysinfo-tethering.xml
%endif
%endif

%files devel
%defattr(-,root,root,-)
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/*.so

