export const fixtures = {
 'https://careers-acme.example/apply': {signals:['Lookalike employer domain','Redirect to a credential form'], destination:'https://forms-scam.example/login', tls:'Valid (fixture)'},
 'https://short.example/job': {signals:['Redirect to a credential form'], destination:'https://forms-scam.example/login', tls:'Valid (fixture)'},
 'https://forms-scam.example/login': {signals:['Documented simulated phishing URL'], confirmed:true, destination:'https://forms-scam.example/login', tls:'Valid (fixture)'},
 'https://careers.acme.example/': {signals:[], tls:'Valid (fixture)'},
 'https://short.example/real': {signals:[], destination:'https://careers.acme.example/', tls:'Valid (fixture)'},
 'https://college.example/': {signals:[], tls:'Valid (fixture)'},
 'https://expired.example/': {signals:[], tls:'Expired certificate (fixture)'},
 'https://distrusted.example/': {signals:[], tls:'Known distrust match (synthetic fixture)'}
};
