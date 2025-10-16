#pragma once

#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#if defined(__has_include)
#  if __has_include(<QString>)
#    include <QString>
#    define MINI_GTEST_HAS_QSTRING 1
#  endif
#endif

namespace testing {

class AssertionFailure : public std::runtime_error {
public:
    AssertionFailure(std::string message, const char* file, int line)
        : std::runtime_error(std::move(message)), file_(file), line_(line) {}

    const char* file() const noexcept { return file_; }
    int line() const noexcept { return line_; }

private:
    const char* file_;
    int line_;
};

namespace internal {

struct TestCase {
    std::string suite;
    std::string name;
    std::function<void()> func;
};

inline std::vector<TestCase>& registry()
{
    static std::vector<TestCase> tests;
    return tests;
}

class TestRegistrar {
public:
    TestRegistrar(const char* suite, const char* name, std::function<void()> func)
    {
        registry().push_back(TestCase{suite, name, std::move(func)});
    }
};

struct TestContext {
    bool failed = false;
    std::vector<std::string> messages;
};

inline TestContext& context()
{
    static TestContext ctx;
    return ctx;
}

inline void reset_context()
{
    context() = TestContext{};
}

inline void record_failure(const std::string& message, const char* file, int line)
{
    context().failed = true;
    std::ostringstream oss;
    oss << file;
    if (line > 0) {
        oss << ':' << line;
    }
    oss << ": " << message;
    context().messages.push_back(oss.str());
}

template <typename T, typename = void>
struct is_streamable : std::false_type {};

template <typename T>
struct is_streamable<T, std::void_t<decltype(std::declval<std::ostringstream&>() << std::declval<const T&>())>> : std::true_type {};

template <typename T>
std::string stringify(const T& value)
{
    if constexpr (std::is_same_v<std::decay_t<T>, bool>) {
        return value ? "true" : "false";
    }
#ifdef MINI_GTEST_HAS_QSTRING
    else if constexpr (std::is_same_v<std::decay_t<T>, QString>) {
        return value.toStdString();
    }
#endif
    else if constexpr (is_streamable<T>::value) {
        std::ostringstream oss;
        oss << value;
        return oss.str();
    } else {
        return "<non-streamable>";
    }
}

template <typename L, typename R>
void expect_equal(const L& lhs,
                  const R& rhs,
                  const char* lhsExpr,
                  const char* rhsExpr,
                  const char* file,
                  int line,
                  bool fatal)
{
    if (!(lhs == rhs)) {
        std::ostringstream oss;
        oss << "Expected " << lhsExpr << " == " << rhsExpr
            << ", but got " << stringify(lhs) << " vs " << stringify(rhs);
        record_failure(oss.str(), file, line);
        if (fatal) {
            throw ::testing::AssertionFailure(oss.str(), file, line);
        }
    }
}

inline void expect_true(bool condition,
                        const char* expr,
                        const char* file,
                        int line,
                        bool fatal)
{
    if (!condition) {
        std::ostringstream oss;
        oss << "Expected " << expr << " to be true";
        record_failure(oss.str(), file, line);
        if (fatal) {
            throw ::testing::AssertionFailure(oss.str(), file, line);
        }
    }
}

inline void expect_false(bool condition,
                         const char* expr,
                         const char* file,
                         int line,
                         bool fatal)
{
    if (condition) {
        std::ostringstream oss;
        oss << "Expected " << expr << " to be false";
        record_failure(oss.str(), file, line);
        if (fatal) {
            throw ::testing::AssertionFailure(oss.str(), file, line);
        }
    }
}

} // namespace internal

inline void InitGoogleTest(int*, char**)
{
    // No-op for the minimal test framework.
}

inline int RUN_ALL_TESTS()
{
    auto& tests = internal::registry();
    std::cout << "[==========] Running " << tests.size() << " test(s)." << std::endl;

    int failedCount = 0;
    for (const auto& test : tests) {
        const std::string fullName = test.suite + "." + test.name;
        std::cout << "[ RUN      ] " << fullName << std::endl;
        internal::reset_context();

        try {
            test.func();
        } catch (const AssertionFailure&) {
            // The failure has already been captured in the context.
        } catch (const std::exception& ex) {
            std::ostringstream oss;
            oss << "Unhandled exception: " << ex.what();
            internal::record_failure(oss.str(), "<exception>", 0);
        } catch (...) {
            internal::record_failure("Unhandled unknown exception", "<exception>", 0);
        }

        if (internal::context().failed) {
            ++failedCount;
            std::cout << "[  FAILED  ] " << fullName << std::endl;
            for (const auto& message : internal::context().messages) {
                std::cout << "  " << message << std::endl;
            }
        } else {
            std::cout << "[       OK ] " << fullName << std::endl;
        }
    }

    if (failedCount == 0) {
        std::cout << "[==========] All tests passed." << std::endl;
    } else {
        std::cout << "[==========] " << failedCount << " test(s) failed." << std::endl;
    }

    return failedCount;
}

} // namespace testing

#define TEST(test_suite_name, test_name)                                                      \
    static void test_suite_name##_##test_name##_Test();                                       \
    static ::testing::internal::TestRegistrar test_suite_name##_##test_name##_registrar(      \
        #test_suite_name, #test_name, &test_suite_name##_##test_name##_Test);                 \
    static void test_suite_name##_##test_name##_Test()

#define EXPECT_TRUE(condition)                                                                \
    ::testing::internal::expect_true((condition), #condition, __FILE__, __LINE__, false)

#define EXPECT_FALSE(condition)                                                               \
    ::testing::internal::expect_false((condition), #condition, __FILE__, __LINE__, false)

#define ASSERT_TRUE(condition)                                                                \
    ::testing::internal::expect_true((condition), #condition, __FILE__, __LINE__, true)

#define ASSERT_FALSE(condition)                                                               \
    ::testing::internal::expect_false((condition), #condition, __FILE__, __LINE__, true)

#define EXPECT_EQ(val1, val2)                                                                 \
    ::testing::internal::expect_equal((val1), (val2), #val1, #val2, __FILE__, __LINE__, false)

#define ASSERT_EQ(val1, val2)                                                                 \
    ::testing::internal::expect_equal((val1), (val2), #val1, #val2, __FILE__, __LINE__, true)

#define EXPECT_NE(val1, val2)                                                                 \
    do {                                                                                      \
        if ((val1) == (val2)) {                                                               \
            std::ostringstream gtestMiniStream;                                               \
            gtestMiniStream << "Expected " #val1 " != " #val2;                                \
            ::testing::internal::record_failure(gtestMiniStream.str(), __FILE__, __LINE__);   \
        }                                                                                     \
    } while (false)

#define ASSERT_NE(val1, val2)                                                                 \
    do {                                                                                      \
        if ((val1) == (val2)) {                                                               \
            std::ostringstream gtestMiniStream;                                               \
            gtestMiniStream << "Expected " #val1 " != " #val2;                                \
            ::testing::internal::record_failure(gtestMiniStream.str(), __FILE__, __LINE__);   \
            throw ::testing::AssertionFailure(gtestMiniStream.str(), __FILE__, __LINE__);     \
        }                                                                                     \
    } while (false)
