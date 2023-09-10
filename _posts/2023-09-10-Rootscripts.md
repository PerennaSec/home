---
layout: post
title: Automate Gentoo Workstation Management with Bash Scripting
date: 2023-09-10
desc: Utilize Bash to streamline Gentoo system administration
keywords: blog,website,gentoo,linux,bash,gh-pages,security,network,scripting,PerennaSec,automation
categories:
  - Linux
tags:
  - Automation
  - Security
  - Linux
icon: icon-html
---
*referenced rootscripts can be found here: https://github.com/PerennaSec/rootscripts*

One of my favorite parts of the Gentoo workstation is the manual control the user is afforded over all system processes. When touting the distribution's virtues, many are quick to point out the power and flexibility behind Portage, Gentoo's package manager and system maintainer. Portage goes beyond `emerge`, and its exceptional package management capabilities, to include tools like `eselect`, which can be used to update information related to package repositories, kernel symlinks, and everything in-between. 

When Gentoo users first build out their systems, they're quickly met with Gentoo's most infamously flexible feature: kernel configuration. An essential step in the Gentoo installation process is to decide which features to build in to the kernel, which features to load on-demand as modules, and which features to exclude altogether. It's a process that's meticulous, painstaking, and unavoidable. It's one that users will revisit over and over again, albeit less frequently as the system's daily functions are provided for. 

For the longest time my system existed without trackpad support, because I could not, despite my hours of trawling the kernel features menu, discover which module was needed to enable the kernel to communicate with the trackpad. After a week or two of fruitless Google-Fu, I loaded up a live image of Redcore Linux, a Gentoo-based desktop distribution. A quick `lsmod` *finally* showed me what I needed to see. The missing configuration? `CONFIG_PINCTRL_TIGERLAKE`. Specifically, it's a driver that allows Intel Tigerlake PCH pins to be configured and used as GPIO pins. Without this essential communication, no signals could be relayed back to the kernel. Just as well, it was only a month or two ago that I finally remedied a persistent veracrypt error caused by a missing cryptographic function in the kernel. 

All this to say that some precision, and automation, could go a long way in streamlining the Gentoo user experience. Given the distro's self-reliant nature, it's up to the user to tailor their tools to their needs. I created my Rootscripts as a collection of scripts that aim to do just that: automate tasks that would otherwise be subject to repetitive, manual entry, leaving them more error-prone in the process. Given these are sensitive, kernel-level operations, it's best to allow a properly-vetted script to do the work. 

I once again relied on Gentoo community pillar **pietinger** and his incredible Installation Guide for Paranoid Dummies (https://forums.gentoo.org/viewtopic-t-1112798-start-0.html). This guide leads users through many aspects of configuring a hardened Gentoo desktop, including building a stub kernel signed with user-generated cryptographic keys. At the end of the B2 module he lists general processes and procedures for updating kernel configurations, installing new kernel configurations, and backing up a stable stub kernel to a bootloader like GRUB. Using this skeleton, I composed a couple of scripts to perform a slew of tasks. 

The most vital of these tasks was to successfully sign a kernel, and place it in the proper boot directory. Of equal importance was the ability to sign a stable kernel to an external boot partition, in case future kernel updates lead to system dysfunction. Just as well, every installed kernel module must be signed by signing certificates placed in `/usr/src/linux/certs`. 

After that, I simply needed a way to reliably backup my data to a stage4 tarball, in case a system reinstall was ever necessary. Also included are scripts to assist in Integrity Measurement Architecture, a project I intend to revisit in the future. 

The key to smooth, automated kernel upgrades in this case was the following portage hook:
```sh 
function pre_pkg_preinst() {  
   # This hook signs any out-of-tree kernel modules.  
   if [[ "$(type -t linux-mod_pkg_preinst)" != "function" ]]; then  
       # The package does not seem to install any kernel modules.  
       return  
   fi  
   # Get the signature algorithm used by the kernel.  
   local module_sig_hash="$(grep -Po '(?<=CONFIG_MODULE_SIG_HASH=").*(?=")' "${KERNEL_DIR}/.config")"  
   # Get the key file used by the kernel.  
   local module_sig_key="$(grep -Po '(?<=CONFIG_MODULE_SIG_KEY=").*(?=")' "${KERNEL_DIR}/.config")"  
   module_sig_key="${module_sig_key:-certs/signing_key.pem}"  
   # Path to the key file or PKCS11 URI  
   if [[ "${module_sig_key#pkcs11:}" == "${module_sig_key}" && "${module_sig_key#/}" == "${module_sig_  
key}" ]]; then  
       local key_path="${KERNEL_DIR}/${module_sig_key}"  
   else  
       local key_path="${module_sig_key}"  
   fi  
   # Certificate path  
   local cert_path="${KERNEL_DIR}/certs/signing_key.x509"  
   # Sign all installed modules before merging.  
   find "${D%/}/${INSDESTTREE#/}/" -name "*.ko" -exec "${KERNEL_DIR}/scripts/sign-file" "${module_sig_  
hash}" "${key_path}" "${cert_path}" '{}' \;  
   rm -v /usr/src/linux/certs/signing_key.{pem,x509}  
}
```

With this, the master kernel script is able to lead users to the kernel configuration screen, build the kernel (by default using `make -j8`), sign the kernel, copy the kernel to its appropriate directory, and reinstall/sign any out-of-tree kernel modules (in my case, `virtualbox-guest-additions`). 

Also included in the scripts are basic error checks, which return two different outputs based on the script's exit status:

```sh
 if [ $? -ne 0 ]
    then echo -e "Error(s) Detected! \n"
    echo -e "Please Inspect Syntax, Paths, & Output and Try Again. \n"
    exit
  else
    echo -e "Backup Complete! \n"
    sleep 3
    umount -v ${dirpath}
    exit
  fi
```

One of the most rewarding facets of a bare-bones Linux distribution is the opportunity to create on-the-fly solutions for sticking points within one's day-to-day experience. What better way to apply a learn-in-public, learn-by-doing philosophy than by diving into a Linux experience that demands resourceful, dynamic thinking. What better way is there to learn a language than immersion?
