# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36668 - The system must be configured to audit Object Access - Removable Storage successes.'
control 'V-36668' do
  impact 0.5
  title 'The system must be configured to audit Object Access - Removable Storage successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.  Removable Storage auditing under Object Access records events related to access attempts on file system objects on removable storage devices.'
  tag 'stig', 'V-36668'
  tag severity: 'medium'
  tag checkid: 'C-46853r1_chk'
  tag fixid: 'F-44723r1_fix'
  tag version: 'WN12-AU-000081'
  tag ruleid: 'SV-51601r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> "Audit Removable Storage" with "Success" selected.'
  tag checktext: 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding.

Object Access -> Removable Storage - Success'

# START_DESCRIBE V-36668
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE V-36668

end
