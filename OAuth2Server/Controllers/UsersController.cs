namespace OAuth2Server.Controllers
{
    using System.Linq;
    using System.Web.Mvc;

    using OAuth2Server.Models;

    /// <summary>
    /// This controller shows the users.
    /// </summary>
    public class UsersController : Controller
    {
        private readonly OAuth2ServerDbContext db = new OAuth2ServerDbContext();

        // GET: /Users/
        public ActionResult Index()
        {
            return this.View(this.db.Users.ToList());
        }

        protected override void Dispose(bool disposing)
        {
            this.db.Dispose();
            base.Dispose(disposing);
        }
    }
}