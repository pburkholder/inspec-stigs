# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-PK-000001 - The DoD root certificate must be installed into the Trusted Root Store.'

control 'WN12-PK-000001' do
  impact 0.5
  title 'The DoD root certificate must be installed into the Trusted Root Store.'
  desc '
To ensure secure DoD websites and DoD signed code are properly validated, the system must trust the DoD Root CA 2.  The DoD root certificate will ensure that the trust chain is established for server certificates issued from the DoD CA.
'
  tag 'stig','WN12-PK-000001'
  tag severity: 'medium'
  tag checkid: 'C-WN12-PK-000001_chk'
  tag fixid: 'F-WN12-PK-000001_fix'
  tag version: 'WN12-PK-000001'
  tag ruleid: 'WN12-PK-000001_rule'
  tag fixtext: '
Install the DoD Root CA 2 certificate.  The InstallRoot tool is available on IASE at http://iase.disa.mil/pki-pke/function_pages/tools.html.
'
  tag checktext: '
Verify the DoD Root CA 2 certificate is installed as a Trusted Root Certification Authority using the Certificates MMC snap-in:
Run "MMC".
Select "File", "Add/Remove Snap-in".
Select "Certificates", click "Add".
Select "Computer account", click "Next".
Select "Local computer: (the computer this console is running on)", click "Finish".
Click "OK".
Expand "Certificates" and navigate to "Trusted Root Certification Authorities\Certificates".
Search for "DoD Root CA 2" under "Issued To" in the center pane.

If there is no entry for "DoD Root CA 2", this is a finding.

Select DoD Root CA 2.
Right click and select "Open".
Select the "Details" Tab.
Scroll to the bottom and select "Thumbprint Algorithm".
Verify the Value is "sha1".

If the value for "Thumbprint Algorithm" is not "sha1", this is a finding.

Next select "Thumbprint".

If the value for the "Thumbprint" field is not
"8C:94:1B:34:EA:1E:A6:ED:9A:E2:BC:54:CF:68:72:52:B4:C9:B5:61", this is a finding.
'

# START_DESCRIBE WN12-PK-000001
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-PK-000001

end
