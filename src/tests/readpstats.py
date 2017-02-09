import pstats
p = pstats.Stats('speedtest.prof')
p.sort_stats('tottime')
p.print_stats()
