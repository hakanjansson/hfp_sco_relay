# hfp_sco_relay
This application is intended for test purposes only, it has not been extensively tested and is still work in progress.

**hfp_sco_relay** initializes two HFP connections, one for Audio Gateway role and one for Hands-Free unit role, and relays the SCO audio stream between the two. It registers as a HFP profile with BlueZ but the actual Bluetooth device connections has to be done externally, i.e. using bluetoothctl. Command-line options can be used to specify a log server to which messages and SCO audio packets can be sent for logging.<br/>
Example usage:<br/>
`hfp_sco_relay --log-addr=192.168.1.249 --log-port=4445 --log-level=4 --no-stdout`
<br/><br/>

**log_server** listens for incoming log packets, prints log messages and generates PCM data files of logged SCO audio streams. Command-line options can be used to specify the incoming port and an optional CSV file to write logged SCO audio packets.<br/>
Example usage:<br/>
`log_server --port=4445 --csv=logged_audio.csv`
<br/><br/>
SoX (http://sox.sourceforge.net/) can be used to convert or play the generated PCM data files, e.g to play:<br/>
`play -t raw -r 8000 -b 16 -e signed-integer -c 1 sco_stream__30_73_9B_00_DB_C1__20_70_3A_01_1F_AC.pcm`
<br/><br/>
Convert to wav:<br/>
`sox -t raw -r 8000 -b 16 -e signed-integer -c 1 sco_stream__30_73_9B_00_DB_C1__20_70_3A_01_1F_AC.pcm sco_stream__30_73_9B_00_DB_C1__20_70_3A_01_1F_AC.wav`
<br/><br/>

**test_relay** can be used to test hfp_sco_relay by connecting as AG and/or HF and sending PCM data from file(s) over SCO. Command-line options include options for specifying local Bluetooth controller addresses for AG and HF.<br/>
Example usage:<br/>
`test_relay --relay-addr=20:70:3A:01:1F:AC --hf-addr=30:73:9B:00:DB:C1 --ag-addr=20:73:9B:00:DB:C1 --relay-hf-channel=7 --relay-ag-channel=13 --pcm-in-hf=pcm_in_hf.pcm --pcm-in-ag=pcm_in_ag.pcm`

