import threading

class sleepy(threading.Thread):
	def run(self):
		for _ in range(3):
			print(threading.currentThread().getName() + " is very sleepy.")

wooseock = sleepy(name='WooSeock')
hongkwan = sleepy(name='HongKwan')

wooseock.start()
hongkwan.start()

