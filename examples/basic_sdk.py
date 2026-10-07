from sdk import GuardX
g=GuardX("gx_your_key")
result=g.check_input("What is the capital of France?")
print(result.decision,result.risk_score)
