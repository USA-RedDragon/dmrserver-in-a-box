# DMR Server in a box

Run a DMR network server with a single binary. Includes private and group calls and a Parrot. Perfect for quick deployments in emergency situations. Intended for use with AREDN.

## Current Status

This project is deployed in the Oklahoma AREDN mesh. Future revisions will help clean it up and separate concerns a bit better. Everything is functional so far (excluding potential bugs) but some of the web interface needs polishing. 9990 Parrot and 4000 Unlink are implemented.

## External requirements

Redis and PostgreSQL are required.

## Screenshots

![Lastheard](/doc/Screenshots/lastheard.png)

<details>
  <summary>More? Click to expand</summary>

![Repeaters](doc/Screenshots/repeaters.png)

![Easy Repeater Enrollment](doc/Screenshots/repeaters-easy.png)

![Repeater Management](doc/Screenshots/repeaters-edit.png)

![Talkgroup List](doc/Screenshots/talkgroups.png)

![Talkgroup Ownership](doc/Screenshots/talkgroup-ownership.png)

![User Approva](doc/Screenshots/user-approval.png)
</details>

## Deploying

### Setting up a database

TODO: Add instructions and provide a production-ready Docker-Compose file.

Once a database is made available, run the following commands in `psql` to create a database and user for this service.

```sql
CREATE USER dmr WITH ENCRYPTED PASSWORD 'changeme';
ALTER USER dmr WITH PASSWORD 'new_password';
CREATE DATABASE "dmr";
ALTER DATABASE dmr OWNER TO dmr;
GRANT ALL PRIVILEGES ON DATABASE dmr TO dmr;
\c dmr
GRANT ALL ON schema public TO dmr;
# after the app runs so Parrot call tracking works
INSERT INTO users (id, callsign, password, admin, approved) VALUES (9990,'Parrot','','f','t');
```

## Todos

### Before first release

#### Things the user sees

- Make user admins appointable and implement user suspend in the UI
- Add ability to add and remove talkgroup admins and NCOs in the UI
- Superadmin class that can add and remove admin
- Admin class that can make and delete talkgroups, suspend and enable users, appoint and demote talkgroup owners, and see the master repeater and user list
- Finalize color scheme

#### Things the dev sees

- CI build and release
- Dockerize
- redis auth
- Document deployment
- Paginate APIs
- Rework frontend to not carry around so many objects
- componentize the frontend
- seed an initial user + dummy parrot user

### Soon

- details page for talkgroup with lastheard
- details page for repeater with lastheard
- details page for user with lastheard and repeaters
- users should be able to edit their name and callsign
- error handling needs to be double checked
- Fix MSTCL on master shutdown (signal trap)
- distributed database? Maybe OLSR can help with the "where do I point my pi-star" problem that isn't a SPOF?

### Long Term

- Implement API tests
- Implement UDP server tests
- metrics

## To test

- DMR sms

## Feature ideas

- Setting to use any free slot if possible. (i.e. timeslot routing where both slots are maximally active)
- Admin panels
  - see users where callsign and DMR ID don't match (due to dmr id db drift)
  - server configuration. Basically everything you'd see in env vars
- server allowlist
- server blocklist
- ability to lock down traffic on one timeslot to a list of designated users. Intended for ensuring a timeslot remains open for emergency use)
- channel allowlist (maybe useful?)
- channel blocklist (this seems rife for abuse in some communities. maybe make this configurable by server admin?)
- add the ability for a talkgroup owner to create nets
- add the ability for talkgroup owner or net control operator to start/stop a net check-in
- add the ability for talkgroup owner or net control operator to see and export a check-in list (just query calls DB for TG=tg_id during net check-in period)
