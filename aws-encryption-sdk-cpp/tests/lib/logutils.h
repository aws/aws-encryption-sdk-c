/*
 * These RAII-style logging classes will buffer log entries until .clear() is called on the LoggingRAII object.
 * If a test fails, RUN_TEST will return from main without calling clear, and the destructor on LoggingRAII will dump
 * the buffered log entries for the specific failed test to stderr before exiting.
 */
namespace Aws {
namespace Cryptosdk {
namespace Testing {

class BufferedLogSystem : public Aws::Utils::Logging::FormattedLogSystem {
   private:
    std::mutex logMutex;
    std::vector<Aws::String> buffer;

   public:
    void clear() {
        std::lock_guard<std::mutex> guard(logMutex);

        buffer.clear();
    }

    void dump() {
        std::lock_guard<std::mutex> guard(logMutex);

        for (auto &str : buffer) {
            std::cerr << str;
        }
    }

    void Flush() {}

    BufferedLogSystem(Aws::Utils::Logging::LogLevel logLevel) : FormattedLogSystem(logLevel) {}

   protected:
    // Overrides FormattedLogSystem pure virtual function
    virtual void ProcessFormattedStatement(Aws::String &&statement) {
        std::lock_guard<std::mutex> guard(logMutex);

        buffer.push_back(std::move(statement));
    }
};

class LoggingRAII {
    std::shared_ptr<BufferedLogSystem> logSystem;

   public:
    LoggingRAII() {
        logSystem = Aws::MakeShared<BufferedLogSystem>("LoggingRAII", Aws::Utils::Logging::LogLevel::Info);

        Aws::Utils::Logging::InitializeAWSLogging(logSystem);
    }

    void clear() {
        logSystem->clear();
    }

    ~LoggingRAII() {
        Aws::Utils::Logging::ShutdownAWSLogging();

        logSystem->dump();
    }
};

}  // namespace Testing
}  // namespace Cryptosdk
}  // namespace Aws
