using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using FlareRedact.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace FlareRedact.Tests
{
    public class SerilogTests
    {
        private sealed class Collector : ILogEventSink
        {
            internal readonly List<LogEvent> Events = new List<LogEvent>();

            public void Emit(LogEvent logEvent) => Events.Add(logEvent);
        }

        private static string Render(LogEvent e)
        {
            var writer = new StringWriter();
            e.RenderMessage(writer);
            return writer.ToString();
        }

        [Fact]
        public void WrappingSinkRedactsPropertiesTemplateTextAndExceptions()
        {
            var collector = new Collector();
            using (Logger log = new LoggerConfiguration()
                .WriteTo.FlareRedact(wt => wt.Sink(collector))
                .CreateLogger())
            {
                log.Information("mail {Email} with {Password}", "ada@example.com", "hunter2");
                log.Information("key AKIAIOSFODNN7EXAMPLE in the text, {Count} times", 3);
                log.Information("user {@User}", new { Name = "Ada", Password = "hunter2", Contact = "grace@example.org" });
                log.Error(new InvalidOperationException("db=postgres://admin:s3cretpw@db.internal/app"), "failed");
            }
            Assert.Equal(4, collector.Events.Count);
            string first = Render(collector.Events[0]);
            Assert.DoesNotContain("ada@example.com", first);
            Assert.DoesNotContain("hunter2", first);
            Assert.Equal("\"***\"", collector.Events[0].Properties["Password"].ToString());

            string second = Render(collector.Events[1]);
            Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", second);
            Assert.EndsWith("in the text, 3 times", second);
            Assert.Contains("{Count}", collector.Events[1].MessageTemplate.Text);

            string user = collector.Events[2].Properties["User"].ToString();
            Assert.DoesNotContain("hunter2", user);
            Assert.DoesNotContain("grace@example.org", user);
            Assert.Contains("Ada", user);

            Exception error = collector.Events[3].Exception!;
            Assert.IsType<RedactedException>(error);
            Assert.DoesNotContain("s3cretpw", error.ToString());
            Assert.Equal(typeof(InvalidOperationException).FullName, ((RedactedException)error).OriginalType);
        }

        [Fact]
        public void NumbersAndStructuresUnderSensitiveNamesAreMasked()
        {
            var collector = new Collector();
            using (Logger log = new LoggerConfiguration()
                .WriteTo.FlareRedact(wt => wt.Sink(collector))
                .CreateLogger())
            {
                log.Information("charge {Cvv} for {Amount}, {@Cookie} {Pin}", 123, 1000,
                    new { Name = "connect.sid", Value = "s%3A_SID_abc", Secure = true }, new[] { 1234, 5678 });
            }
            LogEvent logEvent = collector.Events.Single();
            string rendered = Render(logEvent);
            foreach (string leak in new[] { "123", "connect.sid", "s%3A_SID_abc", "1234", "5678" })
            {
                Assert.DoesNotContain(leak, rendered);
            }
            Assert.Equal("\"***\"", logEvent.Properties["Cvv"].ToString());
            Assert.Equal("1000", logEvent.Properties["Amount"].ToString());
            Assert.Contains("Secure: True", logEvent.Properties["Cookie"].ToString());
        }

        [Fact]
        public void ScalarObjectsAreRedactedAsText()
        {
            const string dsn = "postgres://admin:s3cr3tPassw0rd@db.internal:5432/app";
            var collector = new Collector();
            using (Logger log = new LoggerConfiguration()
                .WriteTo.FlareRedact(wt => wt.Sink(collector))
                .CreateLogger())
            {
                // Serilog keeps a Uri as a scalar, so it is rendered with ToString.
                log.Information("db {Url}, {Count} tries", new Uri(dsn), 3);
            }
            LogEvent logEvent = collector.Events.Single();
            Assert.DoesNotContain("s3cr3tPassw0rd", Render(logEvent));
            Assert.DoesNotContain("s3cr3tPassw0rd", logEvent.Properties["Url"].ToString());
            Assert.Equal("3", logEvent.Properties["Count"].ToString());
        }

        [Fact]
        public void EnricherRedactsPropertiesWithWireOptions()
        {
            var collector = new Collector();
            using (Logger log = new LoggerConfiguration()
                .Enrich.WithFlareRedact("{\"mode\":\"label\"}")
                .WriteTo.Sink(collector)
                .CreateLogger())
            {
                log.Information("to {To}", new[] { "ada@example.com", "fine" });
            }
            Assert.Equal("[\"[REDACTED:email]\", \"fine\"]", collector.Events[0].Properties["To"].ToString());
        }
    }

    public class ExtensionsLoggingTests
    {
        private sealed class Entry
        {
            internal string Message = "";
            internal IReadOnlyList<KeyValuePair<string, object?>> State = Array.Empty<KeyValuePair<string, object?>>();
            internal Exception? Exception;
            internal List<object?> Scopes = new List<object?>();
        }

        private sealed class CollectorProvider : ILoggerProvider, ISupportExternalScope
        {
            internal static readonly List<Entry> Entries = new List<Entry>();
            private IExternalScopeProvider? _scopes;

            public ILogger CreateLogger(string categoryName) => new CollectorLogger(this);

            public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopes = scopeProvider;

            public void Dispose()
            {
            }

            private sealed class CollectorLogger : ILogger
            {
                private readonly CollectorProvider _owner;

                internal CollectorLogger(CollectorProvider owner) => _owner = owner;

                public IDisposable? BeginScope<TState>(TState state) where TState : notnull =>
                    _owner._scopes?.Push(state);

                public bool IsEnabled(LogLevel logLevel) => true;

                public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                    Func<TState, Exception?, string> formatter)
                {
                    var entry = new Entry
                    {
                        Message = formatter(state, exception),
                        State = state as IReadOnlyList<KeyValuePair<string, object?>> ?? Array.Empty<KeyValuePair<string, object?>>(),
                        Exception = exception,
                    };
                    _owner._scopes?.ForEachScope((scope, list) => list.Add(scope), entry.Scopes);
                    lock (Entries) Entries.Add(entry);
                }
            }
        }

        [Fact]
        public void ProvidersReceiveRedactedMessagesStateScopesAndExceptions()
        {
            lock (CollectorProvider.Entries) CollectorProvider.Entries.Clear();
            using ServiceProvider services = new ServiceCollection()
                .AddLogging(b => b.AddProvider(new CollectorProvider()).AddFlareRedact())
                .BuildServiceProvider();
            ILogger log = services.GetRequiredService<ILoggerFactory>().CreateLogger("test");
            using (log.BeginScope("request for ada@example.com"))
            {
                log.LogInformation("mail {Email} with {Password}, key AKIAIOSFODNN7EXAMPLE", "ada@example.com", "hunter2");
            }
            log.LogError(new Exception("token ghp_abcdefghijklmnopqrstuvwxyz0123456789"), "failed for {User}", "grace@example.org");

            Entry first = CollectorProvider.Entries[0];
            Assert.DoesNotContain("ada@example.com", first.Message);
            Assert.DoesNotContain("hunter2", first.Message);
            Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", first.Message);
            Dictionary<string, object?> state = first.State.ToDictionary(p => p.Key, p => p.Value);
            Assert.Equal("***", state["Password"]);
            Assert.DoesNotContain("ada@", (string)state["Email"]!);
            string template = (string)state["{OriginalFormat}"]!;
            Assert.StartsWith("mail {Email} with {Password}, key ", template);
            Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", template);
            Assert.DoesNotContain("ada@", Convert.ToString(first.Scopes.Single()));
            Assert.Equal("mail a***@*** with ***, key AKIA***", first.Message);

            Entry second = CollectorProvider.Entries[1];
            Assert.IsType<RedactedException>(second.Exception);
            Assert.DoesNotContain("ghp_abcdefghijklmnopqrstuvwxyz0123456789", second.Exception!.ToString());
            Assert.DoesNotContain("grace@", second.Message);
        }

        [Fact]
        public void NumbersUnderSensitiveNamesAreMasked()
        {
            lock (CollectorProvider.Entries) CollectorProvider.Entries.Clear();
            using ServiceProvider services = new ServiceCollection()
                .AddLogging(b => b.AddProvider(new CollectorProvider()).AddFlareRedact())
                .BuildServiceProvider();
            ILogger log = services.GetRequiredService<ILoggerFactory>().CreateLogger("numbers");
            log.LogInformation("charge {Cvv} for {Amount}, otp {Otp}", 123, 1000, 482913L);

            Entry entry = CollectorProvider.Entries.Single();
            Dictionary<string, object?> state = entry.State.ToDictionary(p => p.Key, p => p.Value);
            Assert.Equal("***", state["Cvv"]);
            Assert.Equal(1000, state["Amount"]);
            Assert.Equal("***", state["Otp"]);
            Assert.Equal("charge *** for 1000, otp ***", entry.Message);
        }

        private sealed class ConnectionInfo
        {
            public override string ToString() => "conn " + Dsn;
        }

        private const string Dsn = "postgres://admin:s3cr3tPassw0rd@db.internal:5432/app";

        // Values the walker does not know (a Uri, a class with its own ToString)
        // used to reach providers as they were, and the message was rendered
        // from them with ToString.
        [Fact]
        public void ObjectsTheWalkerDoesNotKnowAreRedactedAsText()
        {
            lock (CollectorProvider.Entries) CollectorProvider.Entries.Clear();
            using ServiceProvider services = new ServiceCollection()
                .AddLogging(b => b.AddProvider(new CollectorProvider()).AddFlareRedact())
                .BuildServiceProvider();
            ILogger log = services.GetRequiredService<ILoggerFactory>().CreateLogger("objects");
            using (log.BeginScope(new { Dsn }))
            {
                log.LogError("db {Url} via {Connection}, {Count} tries, id {Id}", new Uri(Dsn), new ConnectionInfo(), 3, Guid.Empty);
            }

            Entry entry = CollectorProvider.Entries.Single();
            Assert.DoesNotContain("s3cr3tPassw0rd", entry.Message);
            Assert.Contains("conn postgres://admin:***@db.internal:5432/app", entry.Message);
            Assert.Contains("3 tries", entry.Message);
            Dictionary<string, object?> state = entry.State.ToDictionary(p => p.Key, p => p.Value);
            Assert.DoesNotContain("s3cr3tPassw0rd", Convert.ToString(state["Url"]));
            Assert.DoesNotContain("s3cr3tPassw0rd", Convert.ToString(state["Connection"]));
            Assert.Equal(3, state["Count"]);
            Assert.Equal(Guid.Empty, state["Id"]);
            Assert.DoesNotContain("s3cr3tPassw0rd", Convert.ToString(entry.Scopes.Single()));
        }

        [Fact]
        public void TypeRegisteredProvidersAreWrappedToo()
        {
            lock (CollectorProvider.Entries) CollectorProvider.Entries.Clear();
            using ServiceProvider services = new ServiceCollection()
                .AddLogging(b =>
                {
                    b.Services.AddSingleton<ILoggerProvider, CollectorProvider>();
                    b.AddFlareRedact("{\"mode\":\"label\"}", redactExceptions: false);
                })
                .BuildServiceProvider();
            Assert.All(services.GetServices<ILoggerProvider>(), p => Assert.IsType<RedactingLoggerProvider>(p));
            services.GetRequiredService<ILogger<ExtensionsLoggingTests>>().LogWarning("to ada@example.com");
            Assert.Equal("to [REDACTED:email]", CollectorProvider.Entries.Single().Message);
        }

        [Fact]
        public void MessagesRenderLikeTheFrameworkFormatter()
        {
            lock (CollectorProvider.Entries) CollectorProvider.Entries.Clear();
            using ServiceProvider services = new ServiceCollection()
                .AddLogging(b => b.AddProvider(new CollectorProvider()).AddFlareRedact())
                .BuildServiceProvider();
            ILogger log = services.GetRequiredService<ILoggerFactory>().CreateLogger("t");
            log.LogInformation("n={N,6:0.00} items={Items} none={None} {{braces}}", 3.14159, new[] { 1, 2 }, null);
            log.LogInformation("plain text only");
            Assert.Equal("n=  3.14 items=1, 2 none=(null) {braces}", CollectorProvider.Entries[0].Message);
            Assert.Equal("plain text only", CollectorProvider.Entries[1].Message);
        }

        [Fact]
        public void TemplateHolesSurviveRedaction()
        {
            Policy policy = Policy.Compile(new RedactOptions { Mask = "{x}" });
            string template = StateRedactor.RedactTemplate("token={Token} for {{literal}} ada@example.com", policy);
            Assert.Equal("token={Token} for {{literal}} {{x}}", template);
        }
    }
}
