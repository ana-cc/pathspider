
import pkg_resources

from pathspider.cmd.measure import job_feeder_csv

class FakeSpider:
    def __init__(self):
        self.was_shutdown = False
        self.jobs = []

    def add_job(self, row):
        self.jobs.append(row)

    def shutdown(self):
        self.was_shutdown = True

def test_job_feeder_csv_webtest():
    spider = FakeSpider()

    expected_jobs = [['160.85.31.173', 80, 'mami-project.eu', '1'],
                     ['139.133.210.32', 80, 'erg.abdn.ac.uk', '2'],
                     ['2001:630:241:210:569f:35ff:fe0a:116a', 80, 'erg.abdn.ac.uk', '3'],
                     ['129.132.52.158', 80, 'ecn.ethz.ch', '4'],
                     ['2001:67c:10ec:36c2::61', 80, 'ecn.ethz.ch', '5'],
                     ['139.133.1.4', 80, 'abdn.ac.uk', '6']]

    job_feeder(pkg_resources.resource_filename("pathspider", "tests/data/webtest.csv"), spider)
    assert spider.was_shutdown
    assert spider.jobs == expected_jobs

def test_job_feeder_csv_webtest_newline():
    spider = FakeSpider()

    expected_jobs = [['160.85.31.173', 80, 'mami-project.eu', '1'],
                     ['139.133.210.32', 80, 'erg.abdn.ac.uk', '2'],
                     ['2001:630:241:210:569f:35ff:fe0a:116a', 80, 'erg.abdn.ac.uk', '3'],
                     ['129.132.52.158', 80, 'ecn.ethz.ch', '4'],
                     ['2001:67c:10ec:36c2::61', 80, 'ecn.ethz.ch', '5'],
                     ['139.133.1.4', 80, 'abdn.ac.uk', '6']]

    job_feeder(pkg_resources.resource_filename("pathspider", "tests/data/webtest_newline.csv"), spider)
    assert spider.was_shutdown
    assert spider.jobs == expected_jobs

def test_job_feeder_csv_webtest_badport():
    spider = FakeSpider()

    expected_jobs = [['160.85.31.173', 80, 'mami-project.eu', '1'],
                     ['139.133.210.32', 80, 'erg.abdn.ac.uk', '2'],
                     ['2001:630:241:210:569f:35ff:fe0a:116a', 80, 'erg.abdn.ac.uk', '3'],
                     ['2001:67c:10ec:36c2::61', 80, 'ecn.ethz.ch', '5'],
                     ['139.133.1.4', 80, 'abdn.ac.uk', '6']]

    job_feeder(pkg_resources.resource_filename("pathspider", "tests/data/webtest_badport.csv"), spider)
    assert spider.was_shutdown
    assert spider.jobs == expected_jobs
