I've coded this application which is essentially a GUI around raw transactions plus an ascii-armor format for transactions similar to PGP ascii armor. The result is an implementation of CoinJoin that could conceivably be used today by non-programmers, albeit still vunerable to denial-of-service and other attacks.

In cj-demo.png is a group of screenshots demonstrating the application being used.

Other implementations I've seen require that peers have to want to do a CoinJoin at essentially the same time. Given that bitcoin transaction volume peaks at about 1 tx / second, it is quite unlikely that there will be someone else wanting to transact exactly the same amount as you that is needed for CoinJoin to improve privacy.

A solution might be to allow people to share their transaction parts asynchronously. This application makes no assumptions about how the CoinJoin peers communicate, only that they can send each other ascii-armored transaction parts in a private way. They could post them on Tor hidden service forums, Bitmessage chans, I2P eepsites, Freenet pages or shared some other way. 

Here is the code. One file of python along with vbuterin's pybitcointools and a socks5 library to allow anonymous lookups through tor or a ssh tunnel. Execute run.bat on Windows or ./run.sh on the command line for Linux

bitcointalk thread
https://bitcointalk.org/index.php?topic=730321.msg8254585
