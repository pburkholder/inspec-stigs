# Inspec Profile for STIGs

Based on Security Guides found at [STIG](http://iase.disa.mil/stigs/Pages/index.aspx)

The Security Technical Implementation Guides (STIGs) and the NSA Guides are the configuration standards for DOD IA and IA-enabled devices/systems. Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the Security Technical Implementation Guides (STIGs). The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

## Develop Inspec checks:

I pulle down the stig json file and parsed it through a shitty script to generate the base inspec files and then wrote the checks.
see [read_stig_json.rb](read_stig_json.rb) for generating inspec base
from stig documentation.

## Demo

```
$ vagrant up
...
...
$ vagrant ssh -c "time inspec exec /vagrant/rhel6 --format=progress
........FFFFFFFFF....F.........FFFFF..F......F.F.F......FF.FF.F..F............FF..F.....FFF.....FF.......*....F..F.F......FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF..F.......FF...FF..*..F.FFFF*F..F...F...F.F..F....[DEPRECATION] `passwd.count` is deprecated. Please use `passwd.entries.length` instead. It will be removed in version 1.0.0.
.*..F*FFFFFF..FF.....FF....F...F..F...F...F....F......F.FFFF.*F*.....F....F...FFFFF.........FF.FFF....FF.FFFFFF.FF*FFF.F...F..F.FFFFF.FF........................................*F.*F.........F....F.....FF.F....FFFFFF.

Pending: (Failures listed here are expected and do not affect your suite's status)

  1) Operating System Detection Skipped control due to only_if condition.
     # Not yet implemented
     #
...
...
Failures:

  1) SSH Configuration HostbasedAuthentication should eq "no"
     Failure/Error: DEFAULT_FAILURE_NOTIFIER = lambda { |failure, _opts| raise failure }

       expected: "no"
            got: nil

       (compared using ==)
     # /vagrant/rhel6/controls/V-38612.rb:41:in `block (3 levels) in load_with_context'
...
...
real    1m36.180s
user    0m12.392s
sys 1m6.712s
```

The STIGs are pulled down from https://www.stigviewer.com. The Windows2012 is based on https://www.stigviewer.com/stig/microsoft_windows_server_2012_member_server/2013-07-25/.

Why are we not using the newer https://www.stigviewer.com/stig/windows_server_2012_2012_r2_member_server/? Because the tests there are un-automatable.  For example, the
`The required legal notice must be configured to display before console logon.` is implemented for Win2012 as:
https://www.stigviewer.com/stig/microsoft_windows_server_2012_member_server/2013-07-25/finding/WN12-SO-000022
which reads, in part:

```
Details
Check Text ( C-WN12-SO-000022_chk )
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: LegalNoticeText

Value Type: REG_SZ
Value: See message text below

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
```

But for  Win2012r2 the comparable section reads:

```
Details
Check Text ( None )
None
Fix Text (F-45771r2_fix)
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Message text for users attempting to log on" to the following:

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
```

and good luck automating that....
