/*
So you need to broadcast an alert...
... here's what to do:

1. Copy sendalert.cpp into your bitcoind build directory

2. Decrypt the alert keys
  copy the decrypted file as alertkeys.h into the src/ directory.

3. Modify the alert parameters in sendalert.cpp
  See the comments in the code for what does what.

4. Add sendalert.cpp to the src/Makefile.am so it gets built:

    libbitcoin_server_a_SOURCES = \
      sendalert.cpp \
      ... etc

5. Update init.cpp to launch the send alert thread.
  Define the thread function as external at the top of init.cpp:

    extern void ThreadSendAlert();

  Add this call at the end of AppInit2:

    threadGroup.create_thread(boost::bind(ThreadSendAlert));

6. build bitcoind, then run it with -printalert or -sendalert
  I usually run it like this:
   ./bitcoind -printtoconsole -sendalert

One minute after starting up the alert will be broadcast. It is then
flooded through the network until the nRelayUntil time, and will be
active until nExpiration OR the alert is cancelled.

If you screw up something, send another alert with nCancel set to cancel
the bad alert.
*/
#include "main.h"
#include "net.h"
#include "alert.h"
#include "init.h"
#include "key.h"
#include "clientversion.h"



static const int64_t DAYS = 24 * 60 * 60;

Value sendalert(const Array& params, bool fHelp)
{
   // MilliSleep(60*1000); // Wait a minute so we get connected
    if (!mapArgs.count("-sendalert") && !mapArgs.count("-printalert"))
        return "no sendalert or printalert parameter";
    
    if (fHelp || params.size() < 6)
        throw runtime_error(
            "sendalert <message> <privatekey> <minver> <maxver> <priority> <id> [cancelupto]\n"
            "<message> is the alert text message\n"
            "<privatekey> is base58 hex string of alert master private key\n"
            "<minver> is the minimum applicable internal client version\n"
            "<maxver> is the maximum applicable internal client version\n"
            "<priority> is integer priority number\n"
            "<id> is the alert id\n"
            "[cancelupto] cancels all alert id's up to this number\n"
            "Returns true or false.");

    //
    // Alerts are relayed around the network until nRelayUntil, flood
    // filling to every node.
    // After the relay time is past, new nodes are told about alerts
    // when they connect to peers, until either nExpiration or
    // the alert is cancelled by a newer alert.
    // Nodes never save alerts to disk, they are in-memory-only.
    //
    CAlert alert;
    alert.nRelayUntil   = GetAdjustedTime() + 15 * 60;
    alert.nExpiration   = GetAdjustedTime() + 365 * 60 * 60;
  //  alert.nID           = 1040;  // use https://en.bitcoin.it/wiki/Alerts to keep track of alert IDs
//    alert.nCancel       = 0;   // cancels previous messages up to this ID number

    // These versions are protocol versions
    // 60002 : 0.7.*
    // 60008 : 0.8.7.3/4
    // 70002 : 0.9.* < 0.9.6
    // 70003 : 0.9.6
    // 70005 : 0.9.6.1
    // 70010 : 0.11.2

    alert.strStatusBar = params[0].get_str();
    alert.nMinVer = params[2].get_int();
    alert.nMaxVer = params[3].get_int();
    alert.nPriority = params[4].get_int();
    alert.nID = params[5].get_int();
    if (params.size() > 6)
      alert.nCancel = params[6].get_int();
    else
      alert.nCancel       = 0; 


    // Set specific client version/versions here. If setSubVer is empty, no filtering on subver is done:
    // alert.setSubVer.insert(std::string("/Satoshi:0.7.2/"));

    // Sign

#include "alertkeys.h"
    /*
     * TODO: get private keys from config file or paremeters (params[1])
     */


   const CChainParams& chainparams = Params();

   std::vector<unsigned char> vchTmp(ParseHex((chainparams.NetworkIDString()=="test") ? pszTestNetPrivKey : pszPrivKey));

   /*
    */


   CPrivKey vchPrivKey(vchTmp.begin(), vchTmp.end() );

    CDataStream sMsg(SER_NETWORK, CLIENT_VERSION);
    sMsg << *(CUnsignedAlert*)&alert;
    alert.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());
    CKey key;
    if (!key.SetPrivKey(vchPrivKey, false))
    {
        return("ThreadSendAlert() : key.SetPrivKey failed\n");

    }
    if (!key.Sign(Hash(alert.vchMsg.begin(), alert.vchMsg.end()), alert.vchSig))
    {
        return("ThreadSendAlert() : key.Sign failed\n");

    }

   
    // Test
    CDataStream sBuffer(SER_NETWORK, CLIENT_VERSION);
    sBuffer << alert;
    CAlert alert2;
    sBuffer >> alert2;

     // Process alert
    if(!alert2.ProcessAlert(chainparams.AlertKey(),false))
        return("sendalert: Failed to process alert.\n");
	
/*	
    assert(alert2.vchMsg == alert.vchMsg);
    assert(alert2.vchSig == alert.vchSig);
   // alert.SetNull();
    printf("\nThreadSendAlert:\n");
    printf("hash=%s\n", alert2.GetHash().ToString().c_str());
    printf("%s\n", alert2.ToString().c_str());
    //alert2.print();
    printf("vchMsg=%s\n", HexStr(alert2.vchMsg).c_str());
    printf("vchSig=%s\n", HexStr(alert2.vchSig).c_str());

    // Confirm
    if (!mapArgs.count("-sendalert"))
        return ("no sendalert parameter");
    while (vNodes.size() < 1 && !ShutdownRequested())
        MilliSleep(500);
    if (ShutdownRequested())
        return ("Shutdown()");
#ifdef QT_GUI
    if (ThreadSafeMessageBox("Send alert?", "ThreadSendAlert", wxYES_NO | wxNO_DEFAULT) != wxYES)
        return"";
    if (ThreadSafeMessageBox("Send alert, are you sure?", "ThreadSendAlert", wxYES_NO | wxNO_DEFAULT) != wxYES)
    {
        ThreadSafeMessageBox("Nothing sent", "ThreadSendAlert", wxOK);
        return"";
    }
#endif
*/
    // Send
    printf("ThreadSendAlert() : Sending alert\n");
    int nSent = 0;
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            if (alert.RelayTo(pnode))
            {
                printf("ThreadSendAlert() : Sent alert to %s\n", pnode->addr.ToString().c_str());
                nSent++;
            }
        }
    }
    printf("ThreadSendAlert() : Alert sent to %d nodes\n", nSent);
    return "";
}
