from app.db.database import Base,engine,SessionLocal
from app.db.models.models import Organization,User,Application,Policy,PolicyRule
from app.core.security import hash_password
Base.metadata.create_all(engine)
db=SessionLocal()
if not db.query(User).filter(User.email=='demo@guardx.local').first():
    o=Organization(name='GuardX Demo');db.add(o);db.flush();u=User(email='demo@guardx.local',password_hash=hash_password('DemoPass123!'),role='OWNER',organization_id=o.id);db.add(u);a=Application(organization_id=o.id,name='Demo AI Assistant');db.add(a);p=Policy(organization_id=o.id,name='Demo Safety Policy');db.add(p);db.flush();db.add_all([PolicyRule(policy_id=p.id,category='credential_exposure',action='BLOCK'),PolicyRule(policy_id=p.id,category='financial_transaction',action='HUMAN_REVIEW')]);db.commit();print('Demo login: demo@guardx.local / DemoPass123!')
else: print('Demo account already exists.')
db.close()
