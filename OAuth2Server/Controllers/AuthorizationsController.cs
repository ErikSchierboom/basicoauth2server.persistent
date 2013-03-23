namespace OAuth2Server.Controllers
{
    using System.Data.Entity;
    using System.Linq;
    using System.Web.Mvc;

    using OAuth2Server.Models;

    /// <summary>
    /// This controller shows the authorizations.
    /// </summary>
    public class AuthorizationsController : Controller
    {
        private readonly OAuth2ServerDbContext db = new OAuth2ServerDbContext();

        // GET: /Authorizations/
        public ActionResult Index()
        {
            var authorizations = this.db.Authorizations.Include(a => a.Client).Include(a => a.User);
            return View(authorizations.ToList());
        }

        protected override void Dispose(bool disposing)
        {
            this.db.Dispose();
            base.Dispose(disposing);
        }
    }
}