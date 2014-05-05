//===
// by xolokram/TB
// 2014 *yey*
//===

#include <iostream>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <map>
#include <boost/uuid/sha1.hpp>

#include "json/json_spirit.h"

using namespace json_spirit;

#include "main_poolminer.h"

#include "hex.h"

#if defined(__GNUG__) && !defined(__MINGW32__) && !defined(__MINGW64__)
#include <sys/syscall.h>
#include <sys/time.h> //depr?
#include <sys/resource.h>
#elif defined(__MINGW32__) || defined(__MINGW64__)
#include <windows.h>
#endif

#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))

#define VERSION_MAJOR 1
#define VERSION_MINOR 1
#define VERSION_EXT "a"

/*********************************
* global variables, structs and extern functions
*********************************/

bool running;
size_t thread_num_max;
static unsigned char pool_fee_percent;
static unsigned short developer_fee_id;
static size_t miner_id;
static boost::asio::ip::tcp::socket* socket_to_server; //connection socket
static boost::posix_time::ptime t_start; //for stats
uint64 totalShareCount; //^
static std::map<int,unsigned long> statistics; //^
static volatile int submitting_share;
std::string pool_username;
std::string pool_password;

/*********************************
* helping functions
*********************************/

void convertDataToBlock(unsigned char* blockData, CBlock& block) {
	{
		std::stringstream ss;
		for (int i = 7; i >= 0; --i)
			ss << std::setw(8) << std::setfill('0') << std::hex << *((int *)(blockData + 4) + i);
		ss.flush();
		block.hashPrevBlock.SetHex(ss.str().c_str());
	}
	{
		std::stringstream ss;
		for (int i = 7; i >= 0; --i)
			ss << std::setw(8) << std::setfill('0') << std::hex << *((int *)(blockData + 36) + i);
		ss.flush();
		block.hashMerkleRoot.SetHex(ss.str().c_str());
	}
	block.nVersion               = *((int *)(blockData));
	block.nTime                  = *((unsigned int *)(blockData + 68));
	block.nBits                  = *((unsigned int *)(blockData + 72));
	block.nNonce                 = *((unsigned int *)(blockData + 76));
	block.bnPrimeChainMultiplier = 0;
}

uint256 hexToHash(std::string hex) {
	CBigNum n;
	// Reverse, too
	std::vector<unsigned char> v = ParseHex(hex);
	std::vector<unsigned char> v2;
	for(int i = v.size() - 1;i >= 0;i--) v2.push_back(v[i]);
	n.setvch(v2);
	return n.getuint256();
}

/*********************************
* class CBlockProviderGW to (incl. SUBMIT_BLOCK)
*********************************/

class CBlockProviderGW : public CBlockProvider {
public:

	CBlockProviderGW() : CBlockProvider(), nTime_offset(0), _block(NULL) {}

	virtual ~CBlockProviderGW() { /* TODO */ }

	virtual unsigned int GetAdjustedTimeWithOffset(unsigned int thread_id, unsigned int counter) {
		return nTime_offset + ((((unsigned int)time(NULL) + thread_num_max) / thread_num_max) * thread_num_max) + thread_id + counter * thread_num_max;
	}
	
	virtual CBlock* getBlock(unsigned int thread_id, unsigned int last_time, unsigned int counter) {
		CBlock* block = NULL;
		{
			boost::shared_lock<boost::shared_mutex> lock(_mutex_getwork);
			if (_block == NULL) return NULL;
			block = new CBlock(*_block);
			//memcpy(block, _block, 80+32+8);
		}
		
		// Create merkle root
		int en2 = rand(); // TODO: Save en2 somewhere
		std::string extranonce2 = HexStr(BEGIN(en2), END(en2));
		std::string cbtxn = coinb1 + extranonce1 + extranonce2 + coinb2;
		//std::cout << "CBTXN: " << cbtxn << std::endl;
		std::vector<unsigned char> coinbase = ParseHex(cbtxn);
		uint256 cbHash = Hash(BEGIN(coinbase[0]), END(coinbase[coinbase.size() - 1]));
		//std::cout << "CBHASH: " << cbHash.GetHex() << std::endl;
		
		unsigned char mr[32];
		
		// Time for some fun memory operations
		unsigned char t[64];
		memcpy(&t[0], cbHash.begin(), 32);
		for(unsigned int i = 0;i < merkle_branch.size();i++) {
			memcpy(&t[32], &ParseHex(merkle_branch[i])[0], 32);
			memcpy(&t[0], Hash(BEGIN(t[0]), END(t[63])).begin(), 32);
		}
		
		// We should now have our merkle root hash in t[0] - t[31]
		memcpy(block->hashMerkleRoot.begin(), &t[0], 32);
		
		//std::cout << "MERKLE ROOT: " << block->hashMerkleRoot.GetHex() << std::endl;
		//std::cout << "EN2: " << extranonce2 << std::endl;
		{
			boost::unique_lock<boost::shared_mutex> lock(_mutex_merkles);
			merkles[block->hashMerkleRoot] = extranonce2;
		}
		
		block->nTime = GetAdjustedTimeWithOffset(0, 0); // No need to mess with times
		//std::cout << "[WORKER" << thread_id << "] block created @ " << block->nTime << std::endl;
		return block;
	}
	
	void setExtraNonce2Len(int len) {
		extranonce2_size = len;
	}
	
	void setExtraNonce1(std::string len) {
		extranonce1 = len;
	}
	
	virtual CBlock* getOriginalBlock() {
		//boost::shared_lock<boost::shared_mutex> lock(_mutex_getwork);
		return _block;
	}
	
	virtual void setBlockTo(CBlock* newblock) {
		CBlock* old_block = NULL;
		{
			boost::unique_lock<boost::shared_mutex> lock(_mutex_getwork);
			old_block = _block;
			_block = newblock;
		}
		if (old_block != NULL) delete old_block;
		CBlockIndex *pindexOld = pindexBest;
		pindexBest = new CBlockIndex(); //=notify worker (this could need a efficient alternative)
		delete pindexOld;
	}

	void setBlocksFromData(mArray params) {
		job_id = params[0].get_str();
		CBlock* block = new CBlock();
		//block->hashPrevBlock = hexToHash(params[1].get_str());
		block->hashPrevBlock.SetHex(params[1].get_str());
		//std::cout << "PREVHASH: " << block->hashPrevBlock.GetHex() << std::endl;
		coinb1 = params[2].get_str();
		coinb2 = params[3].get_str();
		
		//std::cout << "COINB1: " << coinb1 << std::endl;
		//std::cout << "COINB2: " << coinb2 << std::endl;
		
		mArray mb = params[4].get_array();
		merkle_branch.clear();
		for(unsigned int i = 0;i < mb.size();i++) merkle_branch.push_back(mb[i].get_str());
		// Cheat way to turn hex to normal int
		CBigNum c;
		c.setvch(ParseHex(params[5].get_str()));
		block->nVersion = c.getint();
		//std::cout << "VERSION: " << block->nVersion << std::endl;
		c.setvch(ParseHex(params[6].get_str()));
		block->nBits = c.getint();
		//std::cout << "BITS: " << block->nBits << std::endl;
		c.setvch(ParseHex(params[7].get_str()));
		block->nTime = c.getint();
		//std::cout << "TIME: " << block->nTime << std::endl;
		block->nNonce = 0;
		block->bnPrimeChainMultiplier = 0;
		
		unsigned int nTime_local = time(NULL);
		unsigned int nTime_server = block->nTime;
		nTime_offset = nTime_local > nTime_server ? 0 : (nTime_server-nTime_local);
		{
			boost::unique_lock<boost::shared_mutex> lock(_mutex_merkles);
			merkles.clear();
		}
		setBlockTo(block);
	}

	void submitBlock(CBlock *block, unsigned int thread_id) {
		if (socket_to_server != NULL) {
			
			//std::cout << block->GetHeaderHash().GetHex() << std::endl;
			//std::cout << block->bnPrimeChainMultiplier.ToString() << std::endl;
			
			std::string extranonce2 = "";
			
			// Get mapped extranonce
			{
				boost::unique_lock<boost::shared_mutex> lock(_mutex_merkles);
				extranonce2 = merkles[block->hashMerkleRoot]; // Should always work if worker threads are updating
			}
			if(extranonce2 == "") extranonce2 = "ffffffff"; // So that we dont crash in case of a problem, but the share will be invalid
			
			// Encode time, nonce, and primemultiplier
			std::string time = HexStr(BEGIN(block->nTime), END(block->nTime));
			std::string nonce = HexStr(BEGIN(block->nNonce), END(block->nNonce));
			std::string pm = block->bnPrimeChainMultiplier.GetHex();
			
			
			// Prepare the JSON packet
			Object submit_msg;
			Array params;
			
			params.push_back(pool_username);
			params.push_back(job_id);
			params.push_back(extranonce2);
			params.push_back(time);
			params.push_back(nonce);
			params.push_back(pm);
			
			submit_msg.push_back(Pair("params", params));
			submit_msg.push_back(Pair("id", rand() % 999000 + 1000));
			submit_msg.push_back(Pair("method", "mining.submit"));
			
			// Send the line
			
			if(socket_to_server != NULL) boost::asio::write(*socket_to_server, boost::asio::buffer(write(submit_msg) + "\n"));
			
			totalShareCount++;
		}
	}

protected:
	std::string job_id;
	std::string coinb1;
	std::string extranonce1;
	std::string coinb2;
	int extranonce2_size;
	
	boost::shared_mutex _mutex_merkles;
	std::map<uint256, std::string> merkles;
	
	std::vector<std::string> merkle_branch;

	unsigned int nTime_offset;
	boost::shared_mutex _mutex_getwork;
	CBlock* _block;
};

/*********************************
* multi-threading
*********************************/

class CMasterThreadStub {
public:
	virtual void wait_for_master() = 0;
	virtual boost::shared_mutex& get_working_lock() = 0;
};

class CWorkerThread { // worker=miner
public:

	CWorkerThread(CMasterThreadStub *master, unsigned int id, CBlockProviderGW *bprovider)
		: _working_lock(NULL), _id(id), _master(master), _bprovider(bprovider), _thread(&CWorkerThread::run, this) {
	}

	void run() {
		std::cout << "[WORKER" << _id << "] Hello, World!" << std::endl;
		{
			//<set_priority>
			int priority = -1;
#if defined(__GNUG__) && !defined(__MINGW32__) && !defined(__MINGW64__)
			pid_t tid = (pid_t) syscall (SYS_gettid);
			switch (GetArg("-threadprio", 0)) {
				case 1: priority = 0; break;
				case 2: priority = -1; break;
				default: priority = 1;
			}
			setpriority(PRIO_PROCESS, tid, priority);
#elif defined(__MINGW32__) || defined(__MINGW64__)
			HANDLE th = _thread.native_handle();
			
			switch (GetArg("-threadprio", 0)) {
				case 1: priority = THREAD_PRIORITY_NORMAL; break;
				case 2: priority = THREAD_PRIORITY_HIGHEST; break;
				default: priority = THREAD_PRIORITY_LOWEST;
			}
			if (!SetThreadPriority(th, priority))
				std::cerr << "failed to set thread priority to low" << std::endl;
#endif
			//</set_priority>
		}
		_master->wait_for_master();
		std::cout << "[WORKER" << _id << "] GoGoGo!" << std::endl;
		boost::this_thread::sleep(boost::posix_time::seconds(1));
		primecoin_mine<SPHLIB>(_bprovider,_id); //TODO: optimize the code using SPH,SSE,AVX,etc.pp. #1/2
		std::cout << "[WORKER" << _id << "] Bye Bye!" << std::endl;
	}

	void work() { // called from within master thread
		_working_lock = new boost::shared_lock<boost::shared_mutex>(_master->get_working_lock());
	}

protected:
	boost::shared_lock<boost::shared_mutex> *_working_lock;
	unsigned int _id;
	CMasterThreadStub *_master;
	CBlockProviderGW  *_bprovider;
	boost::thread _thread;
};

class CMasterThread : public CMasterThreadStub {
public:

	CMasterThread(CBlockProviderGW *bprovider) : CMasterThreadStub(), _bprovider(bprovider) {}

	void run() {
		{
			boost::unique_lock<boost::shared_mutex> lock(_mutex_master); //only in this scope
			std::cout << "spawning " << thread_num_max << " worker thread(s)" << std::endl;

			for (unsigned int i = 0; i < thread_num_max; ++i) {
				CWorkerThread *worker = new CWorkerThread(this, i, _bprovider);
				worker->work(); //spawn thread(s)
			}
		}

		boost::asio::io_service io_service;
		boost::asio::ip::tcp::resolver resolver(io_service); //resolve dns
		boost::asio::ip::tcp::resolver::iterator endpoint;
		boost::asio::ip::tcp::resolver::iterator end;
		boost::asio::ip::tcp::no_delay nd_option(true);
		boost::asio::socket_base::keep_alive ka_option(true);

		unsigned char poolnum = 0;
		while (running) {
			boost::asio::ip::tcp::resolver::query query(
				(poolnum == 0) ? GetArg("-poolip", "127.0.0.1") :
				(poolnum == 1 && GetArg("-poolip2", "").length() > 0) ? GetArg("-poolip2", "") :
				(poolnum == 2 && GetArg("-poolip3", "").length() > 0) ? GetArg("-poolip3", "") :
				GetArg("-poolip", "127.0.0.1")
				,
				(poolnum == 0) ? GetArg("-poolport", "3333") :
				(poolnum == 1 && GetArg("-poolport2", "").length() > 0) ? GetArg("-poolport2", "") :
				(poolnum == 2 && GetArg("-poolport3", "").length() > 0) ? GetArg("-poolport3", "") :
				GetArg("-poolport", "1337")
			);
			poolnum = (poolnum + 1) % 3;
			endpoint = resolver.resolve(query);
			boost::scoped_ptr<boost::asio::ip::tcp::socket> socket;
			boost::system::error_code error_socket = boost::asio::error::host_not_found;
			while (error_socket && endpoint != end)
			{
				//socket->close();
				socket.reset(new boost::asio::ip::tcp::socket(io_service));
				boost::asio::ip::tcp::endpoint tcp_ep = *endpoint++;
				std::cout << "connecting to " << tcp_ep << std::endl;
				socket->connect(tcp_ep, error_socket);			
			}
			socket->set_option(nd_option);
			socket->set_option(ka_option);

			if (error_socket) {
				std::cout << error_socket << std::endl;
				boost::this_thread::sleep(boost::posix_time::seconds(10));
				if (GetArg("-exitondisc", 0) == 1)
					running = false;
				continue;
			} else {
				t_start = boost::posix_time::second_clock::local_time();
				totalShareCount = 0;
			}

			// Subscribe
			std::string buf = "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n";
			socket->write_some(boost::asio::buffer(buf));

			socket_to_server = socket.get(); //TODO: lock/mutex

			int reject_counter = 0;
			bool done = false;
			boost::asio::streambuf b;
			while (!done) {
				{
					boost::system::error_code error;
					boost::asio::read_until(*socket_to_server, b, "\n", error);
					if (error == boost::asio::error::eof)
						break; // Connection closed cleanly by peer.
					else if (error) {
						std::cout << error << " @ read_some1" << std::endl;
						break;
					}
					
				}
				
				std::istream is(&b);
				std::string req;
				getline(is, req);
				
				try {
					// Parse with JSON
					mValue v;
					if(read(req, v)) {
						mObject obj = v.get_obj();
						if(obj.count("method") > 0) {
							std::string method = obj["method"].get_str();
							mArray params = obj["params"].get_array();
							
							if(method == "mining.set_difficulty") {
								pool_share_minimum = /*(int)ParseHex(params[0].get_str().substr(0,2))[0];*/6;
								
								std::cout << "Set difficulty to " << pool_share_minimum << std::endl;
							}
							else if(method == "mining.notify") {
								_bprovider->setBlocksFromData(params);
								std::cout << "Work recieved!" << std::endl;
							}
							if(obj.count("id") > 0) { // If no ID, no need to respond
								if(!obj["id"].is_null()) {
									std::stringstream ss;
									ss << "{\"error\": null, \"id\": " << obj["id"].get_int() << ", \"result\": null}\n";
									std::string res = ss.str();
									boost::asio::write(*socket_to_server, boost::asio::buffer(res.c_str(), strlen(res.c_str())));
								}
							}
						}
						else {
							// Result of an operation
							
							// Subscribe result
							int id = obj["id"].get_int();
							mValue res = obj["result"];
							if(id == 1) {
								mArray arr = res.get_array();
								_bprovider->setExtraNonce1(arr[1].get_str());
								_bprovider->setExtraNonce2Len(arr[2].get_int());
								std::cout << "Subscribed for work" << std::endl;
							}
							
							// Authentication result
							else if(id == 2) {
								bool worked = res.get_bool();
								if(worked) std::cout << "Successfully logged in!" << std::endl;
								else std::cout << "Error logging in! Check details and try again!";
							}
							
							// Share submit result
							else if(id >= 1000 && id < 1000000) {
								bool retval = res.get_int();
								if(retval <= 0) {
									std::cout << "Share submission failed!" << std::endl;
									reject_counter++;
									if(reject_counter == 3) {
										std::cout << "Too many rejects. Forcing reconnect..." << std::endl;
										break;
									}
								}
								{
									std::map<int,unsigned long>::iterator it = statistics.find(retval);
									if (it == statistics.end())
										statistics.insert(std::pair<int,unsigned long>(retval,1));
									else
										statistics[retval]++;
									reject_counter = 0;
								}
								stats_running();
							}
						}
					}
					else std::cout << "JSON Parse Error from Server: " << req << std::endl;
				} catch(std::exception e) {
					std::cout << "Exception while processing JSON from pool: " << e.what() << std::endl;
				}
			}

			_bprovider->setBlockTo(NULL);
			socket_to_server = NULL; //TODO: lock/mutex		
			if (GetArg("-exitondisc", 0) == 1) {
				running = false;
			} else {
				std::cout << "no connection to the server, reconnecting in 10 seconds" << std::endl;
				boost::this_thread::sleep(boost::posix_time::seconds(10));
			}
		}
	}

	~CMasterThread() {} //TODO: <-- this

	void wait_for_master() {
		boost::shared_lock<boost::shared_mutex> lock(_mutex_master);
	}

	boost::shared_mutex& get_working_lock() {
		return _mutex_working;
	}

private:

	void wait_for_workers() {
		boost::unique_lock<boost::shared_mutex> lock(_mutex_working);
	}

	CBlockProviderGW  *_bprovider;

	boost::shared_mutex _mutex_master;
	boost::shared_mutex _mutex_working;
	
	// Provides real time stats
	void stats_running() {
		if (!running) return;
		std::cout << std::fixed;
		std::cout << std::setprecision(1);
		boost::posix_time::ptime t_end = boost::posix_time::second_clock::local_time();
		unsigned long rejects = 0;
		unsigned long stale = 0;
		unsigned long valid = 0;
		unsigned long blocks = 0;
		for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it) {
			if (it->first < 0) stale += it->second;
			if (it->first == 0) rejects = it->second;
			if (it->first == 1) blocks = it->second;
			if (it->first > 1) valid += it->second;
		}
		std::cout << "[STATS] " << boost::posix_time::second_clock::local_time() << " | ";
		for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it)
			if (it->first > 1)
				std::cout << it->first << "-CH: " << it->second << " (" <<
				  ((valid+blocks > 0) ? (static_cast<double>(it->second) / static_cast<double>(valid+blocks)) * 100.0 : 0.0) << "% | " <<
				  ((valid+blocks > 0) ? (static_cast<double>(it->second) / (static_cast<double>((t_end - t_start).total_seconds()) / 3600.0)) : 0.0) << "/h), ";
		if (valid+blocks+rejects+stale > 0) {
			std::cout << "VL: " << valid+blocks << " (" << (static_cast<double>(valid+blocks) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
			std::cout << "RJ: " << rejects << " (" << (static_cast<double>(rejects) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
			std::cout << "ST: " << stale << " (" << (static_cast<double>(stale) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
		} else {
			std::cout <<  "VL: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "RJ: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "ST: " << 0 << " (" << 0.0 << "%)" << std::endl;
		}
	}
};

/*********************************
* exit / end / shutdown
*********************************/

void exit_handler() {
	//cleanup for not-retarded OS
	if (socket_to_server != NULL) {
		socket_to_server->close();
		socket_to_server = NULL;
	}
	running = false;
}

#if defined(__MINGW32__) || defined(__MINGW64__)

//#define WIN32_LEAN_AND_MEAN
//#include <windows.h>

BOOL WINAPI ctrl_handler(DWORD dwCtrlType) {
	//'special' cleanup for windows
	switch(dwCtrlType) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT: {
			if (socket_to_server != NULL) {
				socket_to_server->close();
				socket_to_server = NULL;
			}
			running = false;
		} break;
		default: break;
	}
	return FALSE;
}

#elif defined(__GNUG__) && !defined(__APPLE__)

static sighandler_t set_signal_handler (int signum, sighandler_t signalhandler) {
   struct sigaction new_sig, old_sig;
   new_sig.sa_handler = signalhandler;
   sigemptyset (&new_sig.sa_mask);
   new_sig.sa_flags = SA_RESTART;
   if (sigaction (signum, &new_sig, &old_sig) < 0)
      return SIG_ERR;
   return old_sig.sa_handler;
}

void ctrl_handler(int signum) {
	exit(1);
}

#endif

/*********************************
* main - this is where it begins
*********************************/
int main(int argc, char **argv)
{
	// ### DO -NOT- REMOVE
	std::cout << "********************************************" << std::endl;
	std::cout << "*** XoloStrataMiner - Primecoin Pool Miner v" << VERSION_MAJOR << "." << VERSION_MINOR << VERSION_EXT << std::endl;
	std::cout << "*** by xolokram/TB - visit www.beeeeer.org" << std::endl;
	std::cout << "*** ported for use with the stratum protocol by KillerByte - visit xpool.xram.co" << std::endl;
	std::cout << "***" << std::endl;
	std::cout << "*** thanks to Sunny King & mikaelh" << std::endl;
	std::cout << "*** press CTRL+C to exit" << std::endl;
	std::cout << "********************************************" << std::endl;
	std::cout << "***" << std::endl;
	std::cout << "*** CAUTION:" << std::endl;
	std::cout << "*** This is primecoin mining software; if you don't know what this means," << std::endl;
	std::cout << "*** don't want to mine primecoins, or you've found this on your PC" << std::endl;
	std::cout << "*** without prior knowledge, please contact 'KillerByte' on" << std::endl;
	std::cout << "*** peercointalk.org, or via IRC at #xrampool on FreeNode" << std::endl;
	std::cout << "***" << std::endl;
	std::cout << "********************************************" << std::endl;

	//TODO: optimize the code using SPH,SSE,AVX,etc.pp. #2/2

	t_start = boost::posix_time::second_clock::local_time();
	totalShareCount = 0;
	running = true;

#if defined(__MINGW32__) || defined(__MINGW64__)
	SetConsoleCtrlHandler(ctrl_handler, TRUE);
#elif defined(__GNUG__) && !defined(__APPLE__)
	set_signal_handler(SIGINT, ctrl_handler);
#endif

	const int atexit_res = std::atexit(exit_handler);
	if (atexit_res != 0)
		std::cerr << "atexit registration failed, shutdown will be (more) dirty!!" << std::endl;
		
	/*if (argc < 2) {
		std::cerr << "usage: " << argv[0] << " -poolfee=<fee-in-%> -poolip=<ip> -poolport=<port> -pooluser=<user> -poolpassword=<password>" << std::endl;
		return EXIT_FAILURE;
	}*/

	// init everything:
	ParseConfigFile("xolominer.cfg");
	ParseParameters(argc, argv);

	fDebug = GetBoolArg("-debug");
	pool_share_minimum = (unsigned int)GetArg("-poolshare", 7);
	//
	socket_to_server = NULL;
	pindexBest = NULL;
	thread_num_max = GetArg("-genproclimit", 1); //TODO: what about boost's hardware_concurrency() ?
	pool_fee_percent = GetArg("-poolfee", 2);
	developer_fee_id = GetArg("-devfeeid", 0);
	miner_id = GetArg("-minerid", 0);
	pool_username = GetArg("-pooluser", "");
	pool_password = GetArg("-poolpassword", "");

	if (thread_num_max < 1) {
		std::cerr << "error: unsupported number of threads" << std::endl;
		return EXIT_FAILURE;
	}
	
	if (pool_fee_percent < 1 || pool_fee_percent > 100) {
		std::cerr << "usage: " << "please use a pool fee between [1 , 100]" << std::endl;
		return EXIT_FAILURE;
	}

	if (miner_id > 65535) {
		std::cerr << "usage: " << "please use a miner id between [0 , 65535]" << std::endl;
		return EXIT_FAILURE;
	}
	
	{ //password to sha1
		boost::uuids::detail::sha1 sha;
		sha.process_bytes(pool_password.c_str(), pool_password.size());
		unsigned int digest[5];
		sha.get_digest(digest);
		std::stringstream ss;
		ss << std::setw(5) << std::setfill('0') << std::hex << (digest[0] ^ digest[1] ^ digest[4]) << (digest[2] ^ digest[3] ^ digest[4]);
		pool_password = ss.str();
	}
	
	std::cout << "* pool: " << GetArg("-poolip", "127.0.0.1") << ":" << GetArg("-poolport", "1337");
	if (GetArg("-poolip2", "").length() > 0) {
		std::cout << " (" << GetArg("-poolip2", "") << ":" << GetArg("-poolport2", "<error>");
		if (GetArg("-poolip3", "").length() > 0)
			std::cout << ", " << GetArg("-poolip3", "") << ":" << GetArg("-poolport3", "<error>");
		std::cout << ")";
	}
	std::cout << std::endl;
	std::cout << "* user: " << pool_username << " #" << miner_id << std::endl;
	std::cout << "* pool fee: " << (int)pool_fee_percent << "% (developer fee ID: " << developer_fee_id << ")" << std::endl;
	std::cout << "* local start time: " << t_start << std::endl;
	std::cout << "* using " << thread_num_max << " ";
	switch (GetArg("-threadprio", 0)) {
		case 1: std::cout << "high-priority"; break;
		case 2: std::cout << "VERY-HIGH-PRIORITY"; break;
		default: std::cout << "low-priority";
	}
	std::cout << " thread(s)" << std::endl;
	std::cout << "********************************************" << std::endl;
	
	pindexBest = new CBlockIndex();

	GeneratePrimeTable();

	//start mining:
	CBlockProviderGW* bprovider = new CBlockProviderGW();
	CMasterThread *mt = new CMasterThread(bprovider);
	mt->run();

	//ok, done.
	return EXIT_SUCCESS;
}

/*********************************
* and this is where it ends
*********************************/
