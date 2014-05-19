Name: gsignond-plugin-oauth
Summary: OAuth plugin for GLib based Single Sign-On
Version: 1.0.0
Release: 1
Group: Security/Accounts
License: LGPL-2.1+
Source: %{name}-%{version}.tar.gz
Source1: %{name}.manifest
URL: https://01.org/gsso
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires: pkgconfig(glib-2.0) >= 2.30
BuildRequires: pkgconfig(gsignond) >= 1.0.0
BuildRequires: pkgconfig(gnutls)
BuildRequires: pkgconfig(libsoup-2.4)
BuildRequires: json-glib-devel


%description
%{summary}.


%package doc
Summary:    Documentation files for %{name}
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description doc
%{summary}.


%prep
%setup -q -n %{name}-%{version}
cp %{SOURCE1} .


%build
%configure 
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
%make_install


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%manifest %{name}.manifest
%doc AUTHORS COPYING.LIB INSTALL NEWS README
%{_libdir}/gsignond/gplugins/liboauth*.so


%files doc
%defattr(-,root,root,-)
%{_datadir}/gtk-doc/html/%{name}/*

