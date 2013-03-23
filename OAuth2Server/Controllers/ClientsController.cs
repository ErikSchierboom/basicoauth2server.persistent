namespace OAuth2Server.Controllers
{
    using System.Linq;
    using System.Web.Mvc;

    using OAuth2Server.Models;

    /// <summary>
    /// This controller shows the clients.
    /// </summary>
    public class ClientsController : Controller
    {
        private readonly OAuth2ServerDbContext db = new OAuth2ServerDbContext();

        // GET: /Clients/
        public ActionResult Index()
        {
            return this.View(this.db.Clients.ToList());
        }

        // GET: /Clients/Details/5
        public ActionResult Details(int id = 0)
        {
            var client = this.db.Clients.Find(id);
            if (client == null)
            {
                return this.HttpNotFound();
            }

            return View(client);
        }

        protected override void Dispose(bool disposing)
        {
            this.db.Dispose();
            base.Dispose(disposing);
        }
    }
}