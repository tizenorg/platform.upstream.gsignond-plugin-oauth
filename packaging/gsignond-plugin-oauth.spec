Name:    gsignond-plugin-oauth
Summary: OAuth plugin for GLib
Version: 1.0.0
Release: 0
Group:   Security/Accounts
License: LGPL-2.1+
Source:  %{name}-%{version}.tar.gz
Source1: %{name}.manifest
URL:     https://01.org/gsso

Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires: pkgconfig(glib-2.0) >= 2.30
BuildRequires: pkgconfig(gsignond) >= 1.0.0
BuildRequires: pkgconfig(gnutls)
BuildRequires: pkgconfig(libsoup-2.4)
BuildRequires: json-glib-devel

%description
OAuth plugin for GLib based on Single Sign-On.


%package doc
Summary:    Documentation for %{name}
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description doc
Documentation files for %{name}.


%prep
%setup -q -n %{name}-%{version}
cp %{SOURCE1} .


%build
%reconfigure
%__make %{?_smp_mflags}


%install
rm -rf %{buildroot}
%make_install


%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%manifest %{name}.manifest
%license COPYING.LIB
%{_libdir}/gsignond/gplugins/liboauth*.so


%files doc
%defattr(-,root,root,-)
%{_datadir}/gtk-doc/html/%{name}/*
