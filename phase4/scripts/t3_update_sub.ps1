$ErrorActionPreference='Continue'
$cfg = 'C:\Temp\wef_subscription.phase4.xml'
$xml = @'
<?xml version="1.0" encoding="UTF-8"?>
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
	<SubscriptionId>SOC002-WS001-Security</SubscriptionId>
	<SubscriptionType>CollectorInitiated</SubscriptionType>
	<Description>SOC-002 Phase 4: Security 4624/4625/4688, PowerShell 4104, Sysmon 1/3</Description>
	<Enabled>true</Enabled>
	<Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
	<ConfigurationMode>Custom</ConfigurationMode>
	<Delivery Mode="Pull">
		<Batching>
			<MaxItems>1</MaxItems>
			<MaxLatencyTime>5000</MaxLatencyTime>
		</Batching>
		<PushSettings>
			<Heartbeat Interval="5000"/>
		</PushSettings>
	</Delivery>
	<Query>
		<![CDATA[
<QueryList><Query Id="0"><Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4688)]]</Select><Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4104)]]</Select><Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=1 or EventID=3)]]</Select></Query></QueryList>
		]]>
	</Query>
	<ReadExistingEvents>false</ReadExistingEvents>
	<TransportName>HTTP</TransportName>
	<TransportPort>5985</TransportPort>
	<ContentFormat>RenderedText</ContentFormat>
	<Locale Language="en-US"/>
	<LogFile>ForwardedEvents</LogFile>
	<PublisherName>Microsoft-Windows-EventCollector</PublisherName>
	<CredentialsType>Default</CredentialsType>
	<EventSources>
		<EventSource Enabled="true">
			<Address>SOC002-WS001.soc002.local</Address>
		</EventSource>
	</EventSources>
</Subscription>
'@
[System.IO.File]::WriteAllText($cfg, $xml, (New-Object System.Text.UTF8Encoding($false)))
"=== Applying via: wecutil ss SOC002-WS001-Security /c:$cfg ==="
wecutil ss SOC002-WS001-Security /c:$cfg
"ExitCode=$LASTEXITCODE"
Start-Sleep -Seconds 6
"=== VERIFY: wecutil gs ==="
wecutil gs SOC002-WS001-Security
"=== VERIFY: wecutil gr ==="
wecutil gr SOC002-WS001-Security
