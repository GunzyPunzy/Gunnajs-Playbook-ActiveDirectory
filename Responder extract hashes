#!/bin/bash
for user in `strings Responder-Session.log | grep "NTLMv2-SSP Hash" | cut -d ":" -f 4-6 | sort -u -f | awk '{$1=$1};1'`
do
echo "[*] search for: $user";
strings Responder-Session.log | grep "NTLMv2-SSP Hash" | grep -i $user | cut -d ":" -f 4-10 |  head -n 1 | awk '{$1=$1};1' >> ntlm-hashes.txt
done
