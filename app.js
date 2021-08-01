const express    = require("express"),
	  bodyParser = require("body-parser"),
	  app        = express(),
	  generator  = require("generate-password"),
	  cryptoJs   = require("crypto-js"),
	  passport   = require("passport"),
	  local      = require("passport-local").Strategy,
	  neo4j      = require("neo4j-driver"),
	  ldapjs 	 = require("ldapjs");
const {NodeSSH} = require('node-ssh');
 
const ssh = new NodeSSH()

//configurations & settings
const driver = neo4j.driver("bolt://localhost", neo4j.auth.basic('neo4j', 'secret'), { disableLosslessIntegers: true });
const session = driver.session();
const client = ldapjs.createClient({
	url: 'ldap://192.168.43.94:389'
});
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");
app.use(require("express-session")({
	secret :" secret key",
	resave : false,
	saveUninitialized : false
}));
app.use(passport.initialize());
app.use(passport.session());
passport.use(new local({
    usernameField: 'nom',
    passwordField: 'mdp',
  },
  (username, password, done)=>{
    let request = 'match(n:admin) return n;'
    session
    .run(request)
    .then((result)=>{
    	if( result.records[0]._fields[0].properties.mdp === cryptoJs.MD5(password).toString())
    		done(null, result.records[0]._fields[0].properties);
    	else
    		done(null, false);
    })
    .catch((err)=>{
    	done(err);
    	console.log(err);
    })
  }
));
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});
const isLoggedIn = function(req, res, next){
	if(req.isAuthenticated())
		return next(); 
	res.redirect("/admin/login");
};
//routes
app.get("/admin/", isLoggedIn, (req, res)=>{
	let request = 'match(n) return (n)'
	session
	.run(request)
	.then((result)=>{
		//console.log(result.records)
		let nbr1=0, nbr2=0, nbr3=0;
		(result.records).forEach((item)=>{
			if(item._fields[0].labels[0]==='etd')
				nbr1++;
		});
		(result.records).forEach((item)=>{
			if(item._fields[0].labels[0]==='ens')
				nbr2++;
		});
		(result.records).forEach((item)=>{
			if(item._fields[0].labels[0] ==='module')
				nbr3++;
		});
		res.render("admin/show",{result: result.records, nbr1: nbr1, nbr2: nbr2, nbr3:nbr3});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.get('/admin/ajouter-etudiant', isLoggedIn, (req, res)=>{
	let password = generator.generate({
		length: 12,
		numbers: true,
		symbols: true
	});
	res.render("admin/add-user", {password: password});
});
app.post('/admin/ajouter-etudiant', isLoggedIn, (req, res)=>{
	console.log(req.body);
	let request = ' match(n:uid) Create (:etd{nom:'+'\''+req.body.nom+'\''+
	',prenom:'+'\''+req.body.prenom+'\''+
	',email:'+'\''+req.body.email+'\''+
	',mdp:'+'\''+cryptoJs.MD5(req.body.mdp)+'\''+
	',filiere:'+'\''+req.body.filiere+'\''+
	',semestre:'+'\''+req.body.semestre+'\''+
	'}) return n;';
	session
	.run(request)
	.then((result)=>{
		client.bind('cn=admin,dc=example,dc=com', 'admin', (err)=>{
		if(err)
			console.log(err);
		else{
			console.log(result.records[0]._fields[0].properties.val);
				console.log("connection LDAP établie!");
				const nombre_s = parseInt(req.body.semestre.charAt(1));
				let grp;
				if(req.body.filiere === 'smi')
					if(nombre_s == 3 || nombre_s == 4)
						grp = 502;
					else if(nombre_s == 1 || nombre_s == 2)
						grp = 501;
					else if(nombre_s == 5 || nombre_s == 6)
						grp = 503;
				else if(req.body.filiere === 'sma')
					if(nombre_s == 3 || nombre_s == 4)
							grp = 505;
					else if(nombre_s == 1 || nombre_s == 2)
							grp = 504;
					else if(nombre_s == 5 || nombre_s == 6)
							grp = 506;
						console.log(grp)
				let user_data = {
					cn: req.body.nom+"-"+req.body.prenom,
					//objectclass: 'inetOrgPerson',
					objectclass: ['inetOrgPerson','posixAccount','top'],
					//objectclass: 'top',
					homedirectory: "/home/users/"+req.body.nom+"-"+req.body.prenom,
					uid: req.body.nom+"-"+req.body.prenom,
					gn: req.body.nom,
					sn: req.body.prenom,
					gidnumber: grp,
					userpassword: "{MD5}"+cryptoJs.MD5(req.body.mdp.trim()),
					uidnumber: result.records[0]._fields[0].properties.val
				};
				let chemin = 'cn='+user_data.cn+',ou=etd,ou=groups,dc=example,dc=com';
				console.log(chemin);
				console.log(user_data);
				client.add(chemin, user_data, (err)=>{
					if(err){
						console.log("pas possible d'ajouter l'utilisateur!");
						console.log(err);
					}
					else{
						console.log("utilisateur ajouter!");
						ssh
  .connect({
    host: '192.168.43.94',
    username: 'pfe',
    password: 'pfe',
    port: 22
  })
  .then(() => {
  	console.log(req.body.filiere+"::"+req.body.semestre);
  	if(req.body.filiere === 'smi')
					if(nombre_s == 3 || nombre_s == 4)
						ssh.execCommand('sudo -S gpasswd -a '+req.body.nom+"-"+req.body.prenom+' etd-smi-s12',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)});
					else if(nombre_s == 5 || nombre_s == 6){
						ssh.execCommand('sudo -S gpasswd -a '+req.body.nom+"-"+req.body.prenom+' etd-smi-s12',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)});
						ssh.execCommand('sudo -S gpasswd -a '+req.body.nom+"-"+req.body.prenom+' etd-smi-s34',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)});
					}
				else if(req.body.filiere === 'sma')
					if(nombre_s == 3 || nombre_s == 4)
							ssh.execCommand('sudo -S gpasswd -a '+req.body.nom+"-"+req.body.prenom+' etd-sma-s12',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)});
					else if(nombre_s == 5 || nombre_s == 6){
						ssh.execCommand('sudo -S gpasswd -a '+req.body.nom+"-"+req.body.prenom+' etd-sma-s12',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)});
						ssh.execCommand('sudo -S gpasswd -a '+req.body.nom+"-"+req.body.prenom+' etd-sma-s34',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)});
					}
    	
  	});
  	/*else if((req.body.semestre == "s5" || req.body.semestre == "s6")&& req.body.filiere == "smi"){
    	ssh.execCommand('sudo -S gpasswd -a'+req.body.nom+"-"+req.body.prenom+' etd-smi-s34',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)
  	});
    	ssh.execCommand('sudo -S gpasswd -a'+req.body.nom+"-"+req.body.prenom+' etd-smi-s12',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)
  	});
  	}
  	if((req.body.semestre == "s3" || req.body.semestre == "s4") && req.body.filiere == "sma")
    	ssh.execCommand('sudo -S gpasswd -a'+req.body.nom+"-"+req.body.prenom+' etd-sma-s12',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)
  	});
  	else if((req.body.semestre == "s5" || req.body.semestre == "s6") && req.body.filiere == "sma"){
    	ssh.execCommand('sudo -S gpasswd -a'+req.body.nom+"-"+req.body.prenom+' etd-sma-s34',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)
  	});
    	ssh.execCommand('sudo -S gpasswd -a'+req.body.nom+"-"+req.body.prenom+' etd-sma-s12',{ stdin: 'pfe\n', pty: true }).then(function(result) {
    	console.log('STDOUT: ' + result.stdout)
    	console.log('STDERR: ' + result.stderr)
  	});
  	}*/
						// const nombre_s = parseInt(req.body.semestre.charAt(1));
						// if(req.body.semestre === 'smi'){
						// 	if(nombre_s >= 3 || nombre_s <= 4){
						// 	let change = new ldapjs.Change({
						// 	operation: 'add',
					 //        modification: {
					 //            gidnumber: 502
					 //        	}
						// 	});
						// 	client.modify(chemin, change, (err)=>{
						// 	if(err)
						// 		console.log("erreur previlige!");
						// 	});
						// }if(nombre_s >= 1 || nombre_s <= 2){
						// 	let change = new ldapjs.Change({
						// 	operation: 'add',
					 //        modification: {
					 //            gidnumber: 501
					 //        	}
						// 	});
						// 	client.modify(chemin, change, (err)=>{
						// 	if(err)
						// 		console.log("erreur previlige!");
						// 	});
						// }if(nombre_s >= 5 || nombre_s <= 6){
						// 	let change = new ldapjs.Change({
						// 	operation: 'add',
					 //        modification: {
					 //            gidnumber: 503
					 //        	}
						// 	});
						// 	client.modify(chemin, change, (err)=>{
						// 	if(err)
						// 		console.log("erreur previlige!");
						// 	});
						// }
						// }
						// else if(req.body.semestre === 'sma'){
						// 	if(nombre_s >= 3 || nombre_s <= 4){
						// 	let change = new ldapjs.Change({
						// 	operation: 'add',
					 //        modification: {
					 //            gidnumber: 505
					 //        	}
						// 	});
						// 	client.modify(chemin, change, (err)=>{
						// 	if(err)
						// 		console.log("erreur previlige!");
						// 	});
						// }if(nombre_s >= 1 || nombre_s <= 2){
						// 	let change = new ldapjs.Change({
						// 	operation: 'add',
					 //        modification: {
					 //            gidnumber: 506
					 //        	}
						// 	});
						// 	client.modify(chemin, change, (err)=>{
						// 	if(err)
						// 		console.log("erreur previlige!");
						// 	});
						// }if(nombre_s >= 5 || nombre_s <= 6){
						// 	let change = new ldapjs.Change({
						// 	operation: 'add',
					 //        modification: {
					 //            gidnumber: 504
					 //        	}
						// 	});
						// 	client.modify(chemin, change, (err)=>{
						// 	if(err)
						// 		console.log("erreur previlige!");
						// 	});
						// }
						// }
					}
				});
			}
		});
		
		session
		.run("match (n:uid) set n.val = n.val+1;")
		.then((result)=>{
			console.log("ok!");
			res.redirect("/admin");
		})
		.catch((err)=>{
			console.log(err);
		});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.get('/admin/ajouter-enseignant', isLoggedIn, (req, res)=>{
		let password = generator.generate({
		length: 12,
		numbers: true,
		symbols: true
	});
	res.render("admin/add-super", {password: password});
});
app.post('/admin/ajouter-enseignant', isLoggedIn, (req, res)=>{
	console.log(req.body.nom);
	let request = 'match (n:uid) Create (:ens{nom:'+'\''+req.body.nom+'\''+
	',prenom:'+'\''+req.body.prenom+'\''+
	',email:'+'\''+req.body.email+'\''+
	',mdp:'+'\''+cryptoJs.MD5(req.body.mdp)+'\''+
	',filiere:'+'\''+req.body.filiere+'\''+
	',tel:'+'\''+(req.body.tel).toString()+'\''+
	'}) return n;';
	console.log(request);
	session
	.run(request)
	.then((result)=>{
		client.bind('cn=admin,dc=example,dc=com', 'admin', (err)=>{
		if(err)
			console.log(err);
		else{
				console.log("connection LDAP établie!");
				const user_data = {
					cn: req.body.nom+'-'+req.body.prenom,
					sn: req.body.nom,
					gn: req.body.prenom,
					uid: req.body.nom+'-'+req.body.prenom,
					gidnumber: 507,
					userpassword: "{MD5}"+cryptoJs.MD5(req.body.mdp),
					homedirectory: "/home/users/"+req.body.nom+"-"+req.body.prenom,
					objectclass: ['inetOrgPerson','posixAccount','top'],
					uidnumber: result.records[0]._fields[0].properties.val
				};
				let chemin = 'cn='+user_data.cn+',ou=ens,ou=groups,dc=example,dc=com';
				client.add(chemin, user_data, (err)=>{
					if(err){
						console.log("pas possible d'ajouter l'utilisateur!");
						console.log(err);
					}
					else{
						console.log("utilisateur ajouter!");
										session
				.run("match (n:uid) set n.val = n.val+1;")
				.then((result)=>{
					res.redirect("/admin");
				})
				.catch((err)=>{
					console.log(err);
				});
					}
						//const nombre_s = parseInt(req.body.semestre.charAt(1));
				});
			}
		});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.get("/admin/liste-edtudiants", isLoggedIn, (req, res)=>{
	let request = 'match(n:etd) return (n)'
	session
	.run(request)
	.then((result)=>{
		//console.log(result.records)
		// (result.records).forEach((item)=>{
		// 	console.log(item._fields[0].properties.name);
		// 	console.log("-----------------");
		// });
		res.render("admin/liste-user",{result:result.records});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.get("/admin/liste-edtudiants/:id/modifier", isLoggedIn, (req, res)=>{
	let request = 'match(n:etd) where ID(n) ='+ req.params.id+' return n;'
	session
	.run(request)
	.then((result)=>{
		console.log(result.records[0]._fields[0].properties)
		res.render("admin/update-user",{etd: result.records[0]._fields[0]});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.post('/admin/liste-edtudiants/:id/modifier', isLoggedIn, (req, res)=>{
	console.log(req.body.nom);
	let request = 'Match (n:etd) where id(n) = '+req.params.id+'set n.nom='+'\''+req.body.nom+'\''+
	',n.email='+'\''+req.body.email+'\''+
	',n.prenom='+'\''+req.body.prenom+'\''+
	',n.filiere='+'\''+req.body.filiere+'\''+
	' return n;';
	console.log(request);
	session
	.run(request)
	.then((result)=>{
		res.redirect("/admin/liste-edtudiants");
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.get("/admin/liste-enseignats", isLoggedIn, (req, res)=>{
	let request = 'match(n:ens) return (n)'
	session
	.run(request)
	.then((result)=>{
		//console.log(result.records)
		// (result.records).forEach((item)=>{
		// 	console.log(item._fields[0].properties.name);
		// 	console.log("-----------------");
		// });
		res.render("admin/liste-super",{result:result.records});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.get("/admin/liste-enseignats/:id/modifier", isLoggedIn, (req, res)=>{
	let request = 'match(n:ens) where ID(n) ='+ req.params.id+' return n;'
	session
	.run(request)
	.then((result)=>{
		console.log(result.records[0]._fields[0].properties)
		res.render("admin/update-super",{etd: result.records[0]._fields[0]});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.post('/admin/liste-enseignats/:id/modifier', isLoggedIn, (req, res)=>{
	console.log(req.body.nom);
	let request = 'Match (n:ens) where id(n) = '+req.params.id+'set n.name='+'\''+req.body.nom+'\''+' return n;';
	console.log(request);
	session
	.run(request)
	.then((result)=>{
		res.redirect("/admin/liste-enseignats");
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.post("/admin/liste-edtudiants/:id", isLoggedIn, (req, res)=>{
	let request = 'match(m:uid) match(n:etd) where ID(n) ='+ req.params.id+' set m.val = m.val-1 with n, n.nom as nom, n.prenom as prenom detach delete n return nom,prenom;'
	session
	.run(request)
	.then((result)=>{
		client.bind('cn=admin,dc=example,dc=com', 'admin', (err)=>{
		if(err)
			console.log(err);
		else{
			console.log("connection LDAP établie!");
			const chemin = "cn="+result.records[0]._fields[0]+"-"+result.records[0]._fields[1]+",ou=etd,ou=groups,dc=example,dc=com";
			console.log(chemin);
			client.del(chemin, (err)=>{
				if(err){
					console.log("pas possible de supprimer l'utilisateur!");
					console.log(err);
				}
				else{
					console.log("utilisateur supprimé!");
					session
				.run("match (n:uid) set n.val = n.val-1;")
				.then((result)=>{
					res.redirect("/admin/liste-edtudiants");
				})
				.catch((err)=>{
					console.log(err);
				});
				}
			});
		}
	});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.post("/admin/liste-enseignats/:id", isLoggedIn, (req, res)=>{
	let request = 'match(m:uid) match(n:ens) where ID(n) ='+ req.params.id+' set m.val = m.val-1 with n, n.nom as nom, n.prenom as prenom detach delete n return nom,prenom;'
	session
	.run(request)
	.then((result)=>{
		client.bind('cn=admin,dc=example,dc=com', 'admin', (err)=>{
		if(err)
			console.log(err);
		else{
			console.log("connection LDAP établie!");
			console.log(result);
			const chemin = "cn="+result.records[0]._fields[0]+"-"+result.records[0]._fields[1]+",ou=ens,ou=groups,dc=example,dc=com";
			client.del(chemin, (err)=>{
				if(err){
					console.log("pas possible de supprimer l'utilisateur!");
					console.log(err);
				}
				else{
					console.log("utilisateur supprimé!");
					session
				.run("match (n:uid) set n.val = n.val-1;")
				.then((result)=>{
					res.redirect("/admin/liste-enseignats");
				})
				.catch((err)=>{
					console.log(err);
				});
					res.redirect("/admin/liste-enseignats");
				}
			});
		}
	});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.get("/admin/modifier", (req, res)=>{
	let request = 'match(n:admin) return n;'
	session
	.run(request)
	.then((result)=>{
		console.log(result.records[0]._fields[0].properties)
		res.render("admin/modify",{admin: result.records[0]._fields[0]});
		//res.render("admin/modify");
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.post("/admin/modifier", (req, res)=>{
	let request = 'Match (n:admin) set n.name='+'\''+req.body.nom+'\', n.mdp=\''+cryptoJs.MD5(req.body.mdp)+'\' return n;';
	session
	.run(request)
	.then((result)=>{
		console.log(result.records[0]._fields[0].properties)
		res.redirect("/admin");
		//res.render("admin/modify");
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.get("/admin/ajouter-module",isLoggedIn, (req, res)=>{
	let request = 'match(n:ens) return (n)'
	session
	.run(request)
	.then((result)=>{
		res.render("admin/module",{result:result.records});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.post("/admin/ajouter-module", isLoggedIn, (req, res)=>{
	//match(m:ens) create (m)-[r:ex]->(n:module{nom:'m3'}) return n,m,r;
	console.log(req.body.nom_complet+"/"+req.body.nom_module);
	let request = "match (m:ens) where ID(m)="+req.body.nom_complet+" create (m)-[r:enseigner]->(n:module{nom:'"+req.body.nom_module+"',semestre:'"+req.body.semestre+"'}) return n,m,r;";
	session
	.run(request)
	.then((result)=>{
		request = "MATCH (e:etd), (n:module{nom: '"+req.body.nom_module+"' })"+
				   " WHERE e.semestre='"+req.body.semestre+"'"+
				   " WITH n, COLLECT(e) AS subs"+
				   " FOREACH(s IN subs | CREATE (n)-[:inscrit]->(s))"+
				   " RETURN *;";
		session.run(request)
		.then((result)=>{
			res.redirect("/admin/");
		}).catch((err)=>{
			console.log(err);
		});
	})
	.catch((err)=>{
		console.log(err);
	});
});
app.get("/admin/login", (req, res)=>{
	res.render("admin/login");
});
app.post("/admin/login", passport.authenticate('local',{
	successRedirect:"/admin",
	failureRedirect:"/admin/login"
	}),
	(req, res)=>{}
);
app.post("/admin/logout", isLoggedIn, (req, res)=>{
	req.logout();
	res.redirect("/admin/login");
});
app.get("/", (req, res)=>{
	res.redirect("/admin");
});
app.get("/admin/modules", isLoggedIn, (req,res)=>{
	let request = "match (n:module)-[:enseigner]-(m:ens) return n,m;"
	session
	.run(request)
	.then((result)=>{
		res.render("admin/modules", {query: result.records});
	}).catch((err)=>{
		res.redirect("/admin");
	});
});
app.post("/admin/modules/:id", isLoggedIn, (req, res)=>{
	let request = "match (n:module) where ID(n)="+req.params.id+" detach delete n;"
	session
	.run(request)
	.then((result)=>{
		res.redirect("admin/modules")
	}).catch((err)=>{
		res.redirect("/admin");
	});
});
app.listen(3000, ()=>{
	console.log("server started!");
}); 

