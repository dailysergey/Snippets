using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using pipWebCenter.Models;
using System.IO;
using Newtonsoft.Json;
using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Collections.Concurrent;
using System.Text;
using Microsoft.EntityFrameworkCore;

namespace pipWebCenter.Handler
{
    public class ActualServices : IHostedService, IDisposable
    {
        public IConfiguration _config;
        private readonly ILogger _logger;
        private Timer _timer;
        private readonly Rabbitmq _rabbitmq;
        private readonly IHttpClientFactory _clientFactory;
        private ConcurrentDictionary<HttpWebRequest, X509Certificate2> _serviceRequests;
        private nContext context;
        public ActualServices(ILogger<ActualServices> logger, IConfiguration config, IHttpClientFactory clientFactory, Rabbitmq rabbitmq)
        {
            _logger = logger;
            _config = config;
            _clientFactory = clientFactory;
            _rabbitmq = rabbitmq;
            _serviceRequests = new ConcurrentDictionary<HttpWebRequest, X509Certificate2>();

            DbContextOptionsBuilder<nContext> builder = new DbContextOptionsBuilder<nContext>();
            builder.UseNpgsql(_config["ConnectionStrings:pgConnection"]);
            context = new nContext(builder.Options);
        }
        public Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Фоновая задача актуализации сервисов запущена.");
            double def = 24;
            double.TryParse(_config["OnceInDayStartServiceCheck"], out def);
            _timer = new Timer(DoInsertOrUpdate, null, TimeSpan.Zero, TimeSpan.FromHours(def));
            return Task.CompletedTask;
        }
        private async void DoInsertOrUpdate(object state)
        {
            try
            {
                var newclient = _clientFactory.CreateClient();
                newclient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                foreach (Some s in _context)
                {
                    ServiceModel services = await GetServicesForOri(s, newclient);
                    if (!(services is null))
                    {
                        InsertServices(s, services);
                    }
                    else
                    {
                        //_dbContext.Entry(ori).CurrentValues.SetValues(ori.Available = 0);
                        s.Available = 0;
                        context.Ori.Update(s);
                        context.SaveChanges();
                        _logger.LogInformation($"Список вернувшихся сервисов пуст, проверьте доступность ОРИ:{s.OriId}");
                    }
                }

            }
            catch (Exception e)
            {
                _logger.LogError(e.Message);
            }
        }

        /// <summary>
        /// Проверка сертификата сервера
        /// </summary>
        /// <param name="sender">request</param>
        /// <param name="certificate">сертификат сервера</param>
        /// <param name="chain">цепочка</param>
        /// <param name="sslPolicyErrors">ошибки</param>
        /// <returns></returns>
        private bool OnCertificateValidation(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            var request = sender as HttpWebRequest;
            SslPolicyErrors errors = sslPolicyErrors;
            if (errors == SslPolicyErrors.None)
                return true;
            X509Chain privateChain = new X509Chain();
            privateChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            X509Certificate2 cert2 = new X509Certificate2(certificate);
            X509Certificate2 caRoot = null;
            if (_serviceRequests.TryRemove(request, out var c))
            {
                caRoot = new X509Certificate2(c);
                privateChain.ChainPolicy.ExtraStore.Add(caRoot);
                privateChain.Build(cert2);
                bool isValid = true;
                if (privateChain.ChainStatus.Length > 1)
                    isValid = false;
                else
                {
                    if (privateChain.ChainStatus[0].Status != X509ChainStatusFlags.UntrustedRoot && privateChain.ChainStatus[0].Status != X509ChainStatusFlags.NoError)
                        isValid = false;
                }
                return isValid;
            }
            else
                return false;
        }

        /// <summary>
        /// Получение сертификатов из БД
        /// </summary>
        /// <param name="req"></param>
        /// <param name="ori"></param>
        /// <returns></returns>
        X509Certificate2 GetClientCertificate(HttpWebRequest req, Some s)
        {
            var certs = context.OriCerts.Find(ori.OriId);
            if (certs != null)
            {
                X509Certificate2 caCert = new X509Certificate2(Encoding.ASCII.GetBytes(certs.CaCert));
                _serviceRequests.TryAdd(req, caCert);

                return new X509Certificate2(Convert.FromBase64String(certs.ClientP12));
            }
            else
            {
                Console.WriteLine($"Сертификат не найден для {ori.OriId}");
                return null;
            }
        }

        /// <summary>
        /// Получаем список сервисов для виртуального ori
        /// </summary>
        /// <param name="s"></param>
        /// <param name="connect"></param>
        /// <returns></returns>
        private async Task<ServiceModel> GetServicesForOri(Some s, HttpClient newclient)
        {
            try
            {
                Uri uri = new Uri(s.uri.Trim('/') + "/services");
                HttpResponseMessage response = new HttpResponseMessage();

                string strservices = String.Empty;

                switch (s.Type)
                {
                    case 0:
                        {
                            if (s.Uri.Contains("http://"))
                            {
                                response = await newclient.GetAsync(oriUri);
                                strservices = await response.Content.ReadAsAsync<string>();
                            }
                            if (s.Uri.Contains("https://"))
                            {
                                HttpWebRequest request = WebRequest.Create(Uri) as HttpWebRequest;
                                request.ServerCertificateValidationCallback += OnCertificateValidation;
                                var clientp12 = GetClientCertificate(request, s);
                                if (clientp12 != null)
                                {
                                    request.ClientCertificates.Add(clientp12);
                                    WebResponse resp = await request.GetResponseAsync();
                                    var respStream = resp.GetResponseStream();
                                    using (var sr = new StreamReader(respStream))
                                    {
                                        strservices = await sr.ReadToEndAsync();
                                    }
                                    respStream.Close();
                                }
                            }
                            break;
                        }
                    case 1:
                        {

                            Uri virt = new Uri(s.uri + $"/services?from_ip={s.From_ip.ToString()}");
                            response = await newclient.GetAsync(virt);
                            strservices = await response.Content.ReadAsAsync<string>();
                            break;
                        }
                    default:
                        break;
                }
                if (response.IsSuccessStatusCode)
                    return JsonConvert.DeserializeObject<ServiceModel>(strservices);
                else
                {
                    _logger.LogInformation(response.ReasonPhrase);
                    return null;
                }
            }
            catch (Exception e)
            {
                _logger.LogError(e.Message);
                return null;
            }
        }

        /// <summary>
        /// Вставляет все сервисы в базу
        /// </summary>
        /// <param name="s"></param>
        /// <param name="servicesvo"></param>
        /// <param name="connect"></param>
        private void InsertServices(Some s, ServiceModel servicesvo)
        {
            try
            {
                s.Available = 1;
                context.Ori.Update(s);
                for (int i = 0; i < servicesvo.elements.Count; i++)
                {
                    if (string.IsNullOrEmpty(servicesvo.elements[i].sni))
                    {
                        servicesvo.elements[i].sni = "empty";
                    }
                    IPAddress ipservice = IPAddress.Parse("127.0.0.1");
                    int port = 80;
                    IPAddress.TryParse(servicesvo.elements[i].si, out ipservice);
                    Int32.TryParse(servicesvo.elements[i].sp.ToString(), out port);
                    Some sni = new Some()
                    {
                        
                    };
                    //Проверка на неповторяемость
                    if (context.Sni.Find(sni.SniId, sni.IpService) is null)
                        context.Sni.Add(sni);
                }
                context.SaveChanges();
                _rabbitmq.SendMessage("destination.update");
            }
            catch (Exception e)
            {
                _logger.LogError(e.Message);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Фоновая задача актуализации сервисов завершается.");
            _timer?.Change(Timeout.Infinite, 0);
            return Task.CompletedTask;
        }
        public void Dispose()
        {
            _timer?.Dispose();
        }
    }
}
