Name:       capi-network-tethering
Summary:    Tethering Framework
Version:    0.0.15
Release:    1
Group:      TO_BE/FILLED_IN
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(dbus-glib-1)
BuildRequires: pkgconfig(capi-base-common)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(vconf)
BuildRequires: cmake

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

%install
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/%{name}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest capi-network-tethering.manifest
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

%changelog
* Wed Apr 10 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.0.15-1
- Fix : Stations data structure for dbus

* Tue Apr 09 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.0.14-1
- TETHERING_ERROR_NOT_PERMITTED is added
- Implement connection timer
- Reference count is used
- Add API : tethering_xxx_ip_forward_status()
- TETHERING_ERROR_NOT_SUPPORT_API is added for tethering_create()
- TETHERING_ERROR_NOT_SUPPORT_API is returned when API is not supported
- sysinfo-tethering.xml is installed depending on build machine

* Sat Feb 16 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.0.13-1
- Wrong linker flags are fixed
- Add API : tethering_wifi_set_ssid()

* Thu Feb 14 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.0.12-1
- APIs are exported
- LOG Format is changed
- fvisibility=hidden is applied and API's return value is checked

* Thu Jan 24 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.0.11-1
- Indications for Wi-Fi tethering setting change are added
- Dbus service / interface / object names are changed

* Tue Jan 15 2013 Seungyoun Ju <sy39.ju@samsung.com> 0.0.10-1
- Wi-Fi tethering state is not checked when its settings are modified

* Fri Nov 02 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.9-1
- Manifest file is added for SMACK

* Mon Aug 20 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.8-1
- Deprecated APIs are removed

* Wed Aug 01 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.7-1
- Managed APIs are implemented for Wi-Fi tethering settings

* Sat Jul 21 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.6-1
- Fix tethering callback issue (JIRA S1-6197)

* Tue Jul 10 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.5
- Getting MAC address API is implemented
- TETHERING_TYPE_ALL case is implemented
- Test code is implemented

* Tue Jun 26 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.4
- All internal APIs are implemented

* Fri Jun 15 2012 Seungyoun Ju <sy39.ju@samsung.com> 0.0.3
- Deprecated API from Glib2-2.32.3 is replaced with new one
