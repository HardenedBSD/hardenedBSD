#!/bin/sh

VENDOR="HardenedBSD"
VENDOR_BASE_REPO=${VENDOR}-base
VENDOR_PORTS_REPO=${VENDOR}

usage()
{
	cat <<EOF
Usage: `basename $0` [options] [commands...]
Options:
	-i	Start in interactive mode
	-h	Show this help
Commands:
	check	Check for available updates
	fetch	Fetch the packages needed to be updated
	install	Install the update
EOF
	exit 1
}

no_err()
{
	echo $@
	exit 0
}

err()
{
	echo $@
	exit 1
}

update_activate_on_reboot()
{
	touch /.${VENDOR}.upgrade
}

update_deactivate_on_reboot()
{
	rm -f /.${VENDOR}.upgrade
}

update_check()
{
	echo "Checking for available updates"
	pkg -o ASSUME_ALWAYS_YES=yes update >/dev/null 2>&1 || err "Cannot update repositories"
	pkg -o ASSUME_ALWAYS_YES=yes upgrade -y -r ${VENDOR_BASE_REPO} -n >/dev/null 2>&1
	base_update=$?
	pkg -o ASSUME_ALWAYS_YES=yes upgrade -y -r ${VENDOR_PORTS_REPO} -n >/dev/null 2>&1
	if [ $? -eq 0 ] && [ "${base_update}" -eq 0 ]; then
		err "No update to install"
	fi
	echo "Updates available"
}

update_fetch()
{
	update_check
	echo "Downloading packages"
	pkg -o ASSUME_ALWAYS_YES=true upgrade -y -r ${VENDOR_BASE_REPO} -F >/dev/null 2>&1 || err "Failed to download the packages"
	pkg -o ASSUME_ALWAYS_YES=true upgrade -y -r ${VENDOR_PORTS_REPO} -F >/dev/null 2>&1 || err "Failed to download the packages"
}

update_install()
{
	if [ ! -f /.${VENDOR}.upgrade ]; then
		# Bootstrap the update
		running_kernel=$(kernel-select -p status)
		if [ -z "${running_kernel}" ]; then
			echo "Cannot find which kernel is present"
			exit 1
		fi
		running_kernel_package=$(pkg query '%n' "${running_kernel}")
		kernel_need_update=$(pkg version -Uqn "${running_kernel_package}" -l '<' | wc -l)
		if [ "${kernel_need_update}" -ne 0 ]; then
			echo "Upgrading the kernel"
			pkg -o ASSUME_ALWAYS_YES=yes upgrade -Uqy "${running_kernel_package}"
			update_activate_on_reboot
			echo "Done"
			if [ "${INTERACTIVE}" -eq 1 ]; then
				echo "Update will install at the next reboot"
				echo "Would you like to reboot now (Yy/Nn) ?"
				read answer
				if [ "${answer}" = "Y" ] || [ "${answer}" = "y" ]; then
					reboot
				fi
			fi
			echo "Please reboot to finish the upgrade"
		else
			pkg -o ASSUME_ALWAYS_YES=true upgrade -y -r ${VENDOR_BASE_REPO} -U
			pkg -o ASSUME_ALWAYS_YES=true upgrade -y -r ${VENDOR_PORTS_REPO} -U
		fi
		exit 0
	fi
	pkg -o ASSUME_ALWAYS_YES=true upgrade -y -r ${VENDOR_BASE_REPO} -U
	pkg -o ASSUME_ALWAYS_YES=true upgrade -y -r ${VENDOR_PORTS_REPO} -U
	update_deactivate_on_reboot
	echo "Upgrade finished, rebooting now"
	sleep 3
	reboot
}

COMMANDS=""
INTERACTIVE=0
while [ $# -ne 0 ]; do
	case "$1" in
		-i)
			INTERACTIVE=1
			shift
			;;
		check|fetch|install)
			COMMANDS="${COMMANDS} $1"
			shift
			;;
		*|-h)
			usage
			;;
	esac
done

if [ "${INTERACTIVE}" -eq 1 ]; then
	echo "Would you like to upgrade now (Yy/Nn) ?"
	read answer
	if [ "${answer}" != "Y" ] && [ "${answer}" != "y" ]; then
		return 0
	fi
fi

if [ -z "${COMMANDS}" ] ; then
	if [ "${INTERACTIVE}" -eq 1 ]; then
		COMMANDS="check fetch install"
	else
		usage
	fi
fi

for command in ${COMMANDS}; do
	update_${command}
done
