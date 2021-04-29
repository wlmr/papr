To see difference between issued revocations and successful revocations:
`echo "number of revocation requests $(grep revoking sim.log | wc -l)\nnumber of successful revocations $(grep customer sim.log | wc -l)"`
