# udpdst
Kernel module - Get original ip of redirected udp packet

# Make
git clone https://github.com/nightcoffee/udpdst.git package/kernel/udpdst
make menuconfig
Select Kernel->Other module->udpdst
make package/kernel/udpdst/compile V=99

# Use
Copy build_dir/target-mips_34kc_uClibc-0.9.33.2/linux-ar71xx_generic/udpdst/udpdst.ko to Router
(you should replace the 'target-mips_34kc_uClibc-0.9.33.2/linux-ar71xx_generic' by your platform)
insmod udpdst.ko
